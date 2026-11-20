#!/usr/bin/env python3
"""Missing operation timings and file-backed keys; no driver/system changes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shlex
import signal
import statistics
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parent
CIPHERS = [f'aes-{bits}-{mode}' for bits in (128,192,256) for mode in ('cbc','ecb','ctr','ofb','cfb')]
CIPHERS += ['aes-128-xts','aes-256-xts']+[f'sm4-{mode}' for mode in ('cbc','ecb','ctr','ofb','cfb')]
LENGTHS = [16,64,256,1024,8192,16384]
PKEYS = ['rsa1024','rsa2048','rsa3072','rsa4096','sm2','dh2048','dh3072','dh4096']
FORMATS = ['pem','der','enc.pem','enc.der']
FIXTURE_PASSPHRASE_ENV = 'KAE_TEST_FILE_PASSPHRASE'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.datetime.now().astimezone().isoformat()


def queues():
    return {str(p):int(p.read_text()) for p in Path('/sys/class/uacce').glob('*/available_instances')}


class Suite:
    def __init__(self,args,scratch):
        self.args,self.scratch=args,Path(scratch)
        self.ssl=args.openssl_prefix/'bin/openssl'
        self.bin=self.scratch/'pkey-file'
        self.lib=args.openssl_prefix/'lib'
        if not (self.lib/'libcrypto.so').exists() and not (self.lib/'libcrypto.dylib').exists():
            self.lib=args.openssl_prefix/'lib64'
        self.records=[]
        self.fixture_passphrase=secrets.token_hex(16)
        self.cases=json.loads(args.cases.read_text()) if args.cases else None
        if self.cases is not None:
            if args.phase!='speed' or args.smoke or not isinstance(self.cases,list) or not self.cases:
                raise ValueError('--cases requires a nonempty list, --phase speed and no --smoke')
            allowed={(a,'decrypt',n,m) for a in CIPHERS for n in LENGTHS for m in ('sync','async32')}
            allowed.update((f'rsa{b}',a,32,m) for b in (1024,2048,3072,4096)
                for a in ('encrypt','decrypt','encrypt-oaep','decrypt-oaep') for m in ('sync','async32'))
            allowed.update(('sm2',a,n,m) for a in ('encrypt','decrypt') for n in (16,64,256,1024)
                for m in ('sync','async32'))
            selected=[(r['algorithm'],r['operation'],r['bytes'],r['mode']) for r in self.cases]
            if len(set(selected))!=len(selected) or not set(selected).issubset(allowed):
                raise ValueError('Invalid or duplicate --cases entries')
        self.prefix=['numactl','--physcpubind='+args.cpus,'--membind='+str(args.memory_node)] if args.cpus else []
        self.fingerprints={str(p):sha(p) for p in [self.ssl,SOURCE/'pkey_file_test.c',SOURCE/'dh_vectors.h',
            SOURCE/'run_operation_tests.py']}
        for kind,directory,filename,expected in [('provider',args.provider_dir,'kae_provider.so',args.expect_provider_sha256),
                                                ('engine',args.engine_dir,'kae.so',args.expect_engine_sha256)]:
            if kind in args.backends:
                if directory is None:
                    raise ValueError(f'--{kind}-dir is required')
                path=directory/filename
                self.fingerprints[str(path)]=sha(path)
                if expected and self.fingerprints[str(path)] != expected:
                    raise ValueError(f'{kind} hash changed')
        if args.phase in ('all','speed') and any(b!='default' for b in args.backends):
            if not args.kae_config_dir or not re.search(r'debug_level\s*=\s*none',
                    (args.kae_config_dir/'kae.cnf').read_text()):
                raise ValueError('Performance requires --kae-config-dir with debug_level=none')
        self.manifest=dict(started=now(),host=os.uname().nodename,system=os.uname().sysname,
            kernel=os.uname().release,source_sha256=self.fingerprints[str(SOURCE/'pkey_file_test.c')],
            hashes=self.fingerprints,queues_before=queues(),phase=args.phase,backends=args.backends,
            main_cpu=args.main_cpu,poll_cpu=args.poll_cpu,cpus=args.cpus,memory_node=args.memory_node,
            repeats=args.repeats,seconds_sec=args.seconds_sec,seconds_pkey=args.seconds_pkey,
            actual_hardware_trace=bool(args.trace_lib),performance_traced=False,
            smoke=args.smoke,cases=self.cases)
        self.write_manifest('manifest-start.json')

    def write_manifest(self,name):
        (self.args.output/name).write_text(json.dumps(self.manifest,indent=2)+'\n')

    def env(self,trace=False):
        env=os.environ.copy()
        for key in list(env):
            if key.startswith('KAE_TEST_') or key in ('LD_PRELOAD','LD_AUDIT','OPENSSL_CONF_INCLUDE'):
                env.pop(key,None)
        env.update(OPENSSL_CONF='/dev/null',
            LD_LIBRARY_PATH=f'{self.lib}:/usr/local/lib',TMPDIR=str(self.scratch))
        env[FIXTURE_PASSPHRASE_ENV]=self.fixture_passphrase
        if self.args.provider_dir:
            env['OPENSSL_MODULES']=str(self.args.provider_dir)
        if self.args.engine_dir:
            env['OPENSSL_ENGINES']=str(self.args.engine_dir)
        if self.args.kae_config_dir:
            env['KAE_CONF_ENV']=str(self.args.kae_config_dir)
        if trace and self.args.trace_lib:
            env['LD_PRELOAD']=str(self.args.trace_lib)
        return env

    def run(self,name,command,backend='default',kind='function',trace=False,**fields):
        log=self.args.output/'logs'/f'{name}.log'
        if log.exists():
            raise ValueError(f'Refusing to overwrite {log}')
        start=time.monotonic()
        bindings={}
        minima=queues()
        with log.open('wb') as stream:
            process=subprocess.Popen(self.prefix+list(map(str,command)),stdout=stream,
                stderr=subprocess.STDOUT,env=self.env(trace),start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic()-start>self.args.timeout:
                        raise TimeoutError(name)
                    if self.args.cpus:
                        try:
                            comm=Path(f'/proc/{process.pid}/comm').read_text().strip()
                            if comm in ('openssl','pkey-file'):
                                for task in Path(f'/proc/{process.pid}/task').glob('*'):
                                    tid=int(task.name)
                                    if tid not in bindings:
                                        os.sched_setaffinity(tid,{self.args.main_cpu if tid==process.pid else self.args.poll_cpu})
                                        bindings[tid]=sorted(os.sched_getaffinity(tid))
                        except (FileNotFoundError,ProcessLookupError):
                            pass
                    for key,value in queues().items():
                        minima[key]=min(minima.get(key,value),value)
                    time.sleep(.02)
                rc=process.wait()
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                process.wait()
                raise
        text=log.read_text(errors='replace')
        record=dict(name=name,backend=backend,kind=kind,rc=rc,elapsed=time.monotonic()-start,
            command=shlex.join(self.prefix+list(map(str,command))),log=str(log.relative_to(self.args.output)),
            trace=trace and bool(self.args.trace_lib),thread_bindings=bindings,queue_minimum=minima,
            lines=[s for s in text.splitlines() if s.startswith(('PASS','FAIL','BENCH','TRACE','+F','+H'))],**fields)
        self.records.append(record)
        with (self.args.output/'runs.jsonl').open('a') as out:
            out.write(json.dumps(record)+'\n')
        print(name,f'rc={rc}',flush=True)
        if rc:
            raise RuntimeError(f'{name}: rc={rc}\n{text[-2000:]}')
        if trace and self.args.trace_lib:
            counts=[tuple(map(int,m)) for m in re.findall(r'TRACE \w+ queue_attempts=\d+ acquired=\d+ send_ok=(\d+) recv_ok=(\d+) send_errors=(\d+)',text)]
            if not counts or any(a!=b or e for a,b,e in counts):
                raise RuntimeError(f'{name}: missing or inconsistent hardware trace')
            if backend!='default' and not sum(c[0] for c in counts):
                raise RuntimeError(f'{name}: hardware path not observed')
            if backend=='default' and any(c[0] for c in counts):
                raise RuntimeError(f'{name}: default reference unexpectedly used hardware')
        return record

    def prepare(self):
        version=self.run('openssl-version',[self.ssl,'version','-a'],kind='inventory')
        self.manifest['openssl_version']=(self.args.output/version['log']).read_text().splitlines()[0]
        self.run('build',[os.environ.get('CC','cc'),'-O2','-g','-Wall','-Wextra','-Werror',
            '-I'+str(self.args.openssl_prefix/'include'),SOURCE/'pkey_file_test.c',
            '-L'+str(self.lib),'-Wl,-rpath,'+str(self.lib),'-lcrypto','-o',self.bin],kind='build')
        for alg in PKEYS:
            self.run('prepare-'+alg,[self.bin,'prepare',alg,self.scratch/alg],kind='fixture')

    def file_tests(self):
        algorithms=['sm2','dh2048','rsa2048'] if self.args.smoke else PKEYS
        for backend in self.args.backends:
            for alg in algorithms:
                sizes=[64] if self.args.smoke and alg=='sm2' else [16,64,256,1024] if alg=='sm2' else [32]
                for fmt in FORMATS:
                    for mode in ('sync','async32'):
                        for size in sizes:
                            for action in (('encrypt','encrypt-oaep') if alg.startswith('rsa') else
                                           ('derive',) if alg.startswith('dh') else ('encrypt',)):
                                rec=self.run(f'file-{backend}-{alg}-{fmt}-{mode}-{action}-{size}',
                                    [self.bin,'check',alg,fmt,backend,mode,self.scratch/alg,action,size,0],
                                    backend,trace=True,algorithm=alg,format=fmt,mode=mode,size=size,operation=action)
                                if not any(s.startswith('PASS file-key ') for s in rec['lines']):
                                    raise RuntimeError('missing file-key result')
            self.cli_files(backend)

    def cli_files(self,backend):
        passin=['-passin',f'env:{FIXTURE_PASSPHRASE_ENV}']
        msg=self.scratch/'message.bin'
        msg.write_bytes(bytes(range(64)))
        def command(be,*args):
            extra=['-engine','kae'] if be=='engine' else ['-provider','default','-provider','kae_provider',
                '-propquery','?provider=kae_provider'] if be=='provider' else ['-provider','default','-propquery','provider=default']
            return [self.ssl,'pkeyutl',*extra,*args]
        def sm2_id(be):
            # The old ENGINE CLI has a fixed default ID and no distid ctrl_str.
            if be=='engine':
                return []
            value='1234567812345678' if backend=='engine' else 'kae-file-sm2-id'
            return ['-pkeyopt','distid:'+value]
        for alg in ['rsa2048','sm2','dh2048'] if self.args.smoke else PKEYS:
            msg.write_bytes(bytes(range(32 if alg.startswith('rsa') else 64)))
            for fmt in FORMATS:
                folder=self.scratch/alg
                form='DER' if fmt.endswith('der') else 'PEM'
                public='pub.der' if form=='DER' else 'pub.pem'
                private=['-keyform',form,'-inkey',folder/('key.'+fmt),*passin]
                pub=['-pubin','-keyform',form,'-inkey',folder/('key.'+public)]
                stem=f'cli-{backend}-{alg}-{fmt}'
                if alg.startswith('rsa'):
                    for padding in ('pkcs1','oaep'):
                        options=['-pkeyopt','rsa_padding_mode:'+padding]
                        if padding=='oaep':
                            options+=['-pkeyopt','rsa_oaep_md:sha256','-pkeyopt','rsa_mgf1_md:sha256']
                        for direction in (0,1):
                            first,second=(backend,'default') if direction==0 else ('default',backend)
                            cipher=self.scratch/'cipher.bin'
                            plain=self.scratch/'plain.bin'
                            for name,be,arguments in [
                                ('encrypt',first,['-encrypt',*pub,*options,'-in',msg,'-out',cipher]),
                                ('decrypt',second,['-decrypt',*private,*options,'-in',cipher,'-out',plain])]:
                                self.run(f'{stem}-{padding}-{direction}-{name}',command(be,*arguments),be,
                                    kind='file-cli',algorithm=alg,format=fmt,size=32,
                                    operation=name+('-oaep' if padding=='oaep' else ''),trace=True)
                            if plain.read_bytes()!=msg.read_bytes():
                                raise RuntimeError(f'{stem}-{padding}: plaintext mismatch')
                elif alg=='sm2':
                    for direction in (0,1):
                        first,second=(backend,'default') if direction==0 else ('default',backend)
                        sig=self.scratch/'signature.bin'
                        cipher=self.scratch/'cipher.bin'
                        plain=self.scratch/'plain.bin'
                        for name,be,args in [
                            ('sign',first,['-sign','-rawin','-digest','sm3',*private,*sm2_id(first),'-in',msg,'-out',sig]),
                            ('verify',second,['-verify','-rawin','-digest','sm3',*pub,*sm2_id(second),'-in',msg,'-sigfile',sig]),
                            ('encrypt',first,['-encrypt',*pub,'-in',msg,'-out',cipher]),
                            ('decrypt',second,['-decrypt',*private,'-in',cipher,'-out',plain])]:
                            self.run(f'{stem}-{direction}-{name}',command(be,*args),be,kind='file-cli',
                                algorithm=alg,format=fmt,operation=name,trace=True)
                        if plain.read_bytes()!=msg.read_bytes():
                            raise RuntimeError(f'{stem}: plaintext mismatch')
                else:
                    for name,be,priv,peer in [('kae',backend,'key','peer'),('reference','default','peer','key')]:
                        self.run(f'{stem}-{name}',command(be,'-derive','-keyform',form,
                            '-inkey',folder/(priv+'.'+fmt),*passin,'-peerform',form,
                            '-peerkey',folder/(peer+'.'+public),'-pkeyopt','dh_pad:1','-out',self.scratch/(name+'.bin')),
                            be,kind='file-cli',algorithm=alg,format=fmt,operation='derive',trace=True)
                    secret=(self.scratch/'kae.bin').read_bytes()
                    if not secret or secret!=(self.scratch/'reference.bin').read_bytes():
                        raise RuntimeError(f'{stem}: shared secret mismatch')

    def cipher_command(self,backend,alg,mode,seconds,size=None):
        # OpenSSL 3.0 fetches ciphers while parsing -evp, before parsing later flags.
        selection=['-engine','kae'] if backend=='engine' else ['-provider','default','-provider','kae_provider',
            '-propquery','provider=kae_provider'] if backend=='provider' else ['-provider','default','-propquery','provider=default']
        cmd=[self.ssl,'speed',*selection,'-elapsed','-seconds',seconds,'-mr','-decrypt','-evp',alg]
        cmd+=['-async_jobs','32'] if mode=='async32' else []
        cmd+=['-bytes',size] if size is not None else []
        return cmd

    def probe_routes(self):
        if not self.args.trace_lib:
            return
        algorithms=['aes-128-cbc','sm4-ctr'] if self.args.smoke else CIPHERS
        for alg in algorithms:
            for mode in ('sync','async32'):
                if self.cases is not None and not any(r['algorithm']==alg and r['mode']==mode for r in self.cases):
                    continue
                for backend in self.args.backends:
                    rec=self.run(f'route-{backend}-{alg}-{mode}',self.cipher_command(backend,alg,mode,1,256),
                        backend,kind='route-probe',trace=True,algorithm=alg,mode=mode,size=256)
                    log=(self.args.output/rec['log']).read_text()
                    requests=int(re.search(r'TRACE cipher .*send_ok=(\d+) ',log)[1])
                    iterations=sum(map(int,re.findall(r'\+R:(\d+):',log)))
                    if backend!='default' and (not iterations or requests<iterations):
                        raise RuntimeError(f'{rec["name"]}: not every cipher iteration reached hardware')

    def speed(self):
        specs=[(f'rsa{bits}',action,32) for bits in (1024,2048,3072,4096)
               for action in ('encrypt','decrypt','encrypt-oaep','decrypt-oaep')]
        specs += [('sm2',action,size) for size in (16,64,256,1024) for action in ('encrypt','decrypt')]
        if self.args.smoke:
            specs=[('rsa2048','encrypt-oaep',32),('rsa2048','decrypt-oaep',32),('sm2','encrypt',64),('sm2','decrypt',64)]
        for repeat in range(1,self.args.repeats+1):
            backends=self.args.backends if repeat%2 else list(reversed(self.args.backends))
            for alg in (['aes-128-cbc','sm4-ctr'] if self.args.smoke else CIPHERS):
                for mode in ('sync','async32'):
                    sizes=[None] if self.cases is None else [n for n in LENGTHS
                        if any(r['algorithm']==alg and r['bytes']==n and r['mode']==mode for r in self.cases)]
                    for size in sizes:
                        for backend in backends:
                            cmd=self.cipher_command(backend,alg,mode,self.args.seconds_sec,size)
                            suffix='' if size is None else '-'+str(size)
                            self.run(f'speed-{backend}-{alg}-decrypt-{mode}{suffix}-r{repeat}',cmd,backend,kind='speed-cipher',
                                algorithm=alg,operation='decrypt',mode=mode,repeat=repeat,size=size,seconds=self.args.seconds_sec)
            for alg,action,size in specs:
                for mode in ('sync','async32'):
                    if self.cases is not None and not any((r['algorithm'],r['operation'],r['bytes'],r['mode'])==
                            (alg,action,size,mode) for r in self.cases):
                        continue
                    for backend in backends:
                        self.run(f'speed-{backend}-{alg}-{action}-{size}-{mode}-r{repeat}',
                            [self.bin,'bench',alg,'pem',backend,mode,self.scratch/alg,action,size,self.args.seconds_pkey],
                            backend,kind='speed-pkey',algorithm=alg,operation=action,size=size,mode=mode,
                            repeat=repeat,seconds=self.args.seconds_pkey)

    def finish(self,error):
        self.manifest.update(finished=now(),passed=error is None,error=error,records=len(self.records),
            queues_after=queues(),hashes_after={p:sha(Path(p)) for p in self.fingerprints})
        if self.manifest['queues_after']!=self.manifest['queues_before'] or self.manifest['hashes_after']!=self.fingerprints:
            self.manifest.update(passed=False,error='queue or binary baseline changed')
        if not self.manifest['passed']:
            self.write_manifest('manifest.json')
            raise RuntimeError(self.manifest['error'])
        samples={}
        for rec in self.records:
            if rec['kind']=='speed-cipher':
                fields=next(s.split(':') for s in rec['lines'] if s.startswith('+F:'))
                header=next(s.split(':') for s in rec['lines'] if s.startswith('+H:'))
                sizes=[rec['size']] if rec.get('size') is not None else LENGTHS
                assert list(map(int,header[1:]))==sizes
                assert fields[2].lower()==rec['algorithm'] and len(fields)==3+len(sizes)
                values=zip(sizes,map(float,fields[3:]))
            elif rec['kind']=='speed-pkey':
                line=next(s for s in rec['lines'] if s.startswith('BENCH pkey-file '))
                values=[(rec['size'],float(re.search(r'ops_per_second=([\d.]+)',line)[1]))]
            else:
                continue
            for size,value in values:
                key=(rec['algorithm'],rec['operation'],size,rec['mode'])
                row=samples.setdefault(key,dict(algorithm=key[0],operation=key[1],bytes=key[2],mode=key[3],
                    unit='B/s' if rec['kind']=='speed-cipher' else 'ops/s',samples={},logs={}))
                row['samples'].setdefault(rec['backend'],[]).append(value)
                row['logs'].setdefault(rec['backend'],[]).append(rec['log'])
        for row in samples.values():
            row['medians']={k:statistics.median(v) for k,v in row['samples'].items()}
            assert all(len(v)==self.args.repeats and min(v)>0 for v in row['samples'].values())
            if 'engine' in row['medians'] and 'provider' in row['medians']:
                row['delta']=row['medians']['provider']/row['medians']['engine']-1
        (self.args.output/'performance.json').write_text(json.dumps(list(samples.values()),indent=2)+'\n')
        self.write_manifest('manifest.json')
        print(f'COMPLETE records={len(self.records)} performance_rows={len(samples)}',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--provider-dir',type=Path)
    parser.add_argument('--engine-dir',type=Path)
    parser.add_argument('--kae-config-dir',type=Path)
    parser.add_argument('--trace-lib',type=Path)
    parser.add_argument('--expect-provider-sha256')
    parser.add_argument('--expect-engine-sha256')
    parser.add_argument('--backends',nargs='+',choices=['engine','provider','default'],default=['engine','provider'])
    parser.add_argument('--phase',choices=['files','speed','all'],default='files')
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--seconds-sec',type=int,default=2)
    parser.add_argument('--seconds-pkey',type=float,default=5)
    parser.add_argument('--timeout',type=int,default=180)
    parser.add_argument('--cpus',default='')
    parser.add_argument('--main-cpu',type=int,default=24)
    parser.add_argument('--poll-cpu',type=int,default=26)
    parser.add_argument('--memory-node',type=int,default=0)
    parser.add_argument('--smoke',action='store_true')
    parser.add_argument('--cases',type=Path,help='JSON array of algorithm/operation/bytes/mode to retest')
    args=parser.parse_args()
    if args.repeats<1 or args.seconds_sec<1 or not 0<args.seconds_pkey<=30:
        parser.error('Invalid repeat count or measurement duration')
    for name in ('openssl_prefix','output','provider_dir','engine_dir','kae_config_dir','trace_lib','cases'):
        value=getattr(args,name)
        if value is not None:
            setattr(args,name,value.resolve())
    if args.output.exists():
        parser.error('--output must name a new directory')
    args.output.mkdir(parents=True,mode=0o700)
    (args.output/'logs').mkdir()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with tempfile.TemporaryDirectory(prefix='scratch-',dir=args.output) as scratch:
        suite=Suite(args,scratch)
        error=None
        try:
            suite.prepare()
            if args.phase in ('all','files'):
                suite.file_tests()
            if args.phase in ('all','speed'):
                suite.probe_routes()
                suite.speed()
        except BaseException as exc:
            error=f'{type(exc).__name__}: {exc}'
        try:
            suite.finish(error)
        except Exception as exc:
            suite.manifest.update(passed=False,error=str(exc),finished=now())
            suite.write_manifest('manifest.json')
            raise


if __name__=='__main__':
    main()
