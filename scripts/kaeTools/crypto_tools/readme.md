## 简介
- crypto_tool提供了快速测试加解密功能的工具，用户可以根据需要编译和运行。

## Openssl RSA握手工具
- 编译运行
    ```shell
        unset OPENSSL_CONF
        cd ssl_socket
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -subj "/C=CN/ST=Beijing/L=Beijing/O=MyCompany/CN=example.com"
        
        export OPENSSL_CONF=`pwd`/../openssl.cnf
        make
        ./ssl_server 10001

        # 重新打开一个终端，并进入当前目录
        export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
        KAE_TLS=DHE-RSA-AES256-GCM-SHA384 ./ssl_client 127.0.0.1 10001
    ```

## OpenSSL SM2握手工具
- 需要使用openEuler系统自带的OpenSSL-1.1.1x或者在openEuler仓库下载安装的OpenSSL-1.1.1x，x代表任意后缀
- 编译运行
    ```shell
        cd sm2_ssl
        unset OPENSSL_CONF

        # 生成自签名CA证书
        openssl ecparam -name SM2 -out SM2.pem
        openssl req -config ./openssl.cnf -nodes -subj '/C=AA/ST=BB/O=CC/OU=DD/CN=root ca' -keyout CA.key -newkey ec:SM2.pem -new -out CA.csr
        openssl x509 -sm3 -req -days 30 -in CA.csr -extfile ./openssl.cnf  -extensions v3_ca -signkey CA.key -out CA.crt

        # 生成服务端签名证书和加密证书
        openssl req -config ./openssl.cnf -nodes -subj '/C=AA/ST=BB/O=CC/OU=DD/CN=server sign' -keyout SS.key -newkey ec:SM2.pem -new -out SS.csr
        openssl x509 -sm3 -req -days 30 -in SS.csr -CA CA.crt -CAkey CA.key -extfile ./openssl.cnf -extensions v3_req -out SS.crt -CAcreateserial
        openssl req -config ./openssl.cnf -nodes -subj '/C=AA/ST=BB/O=CC/OU=DD/CN=server enc' -keyout SE.key -newkey ec:SM2.pem -new -out SE.csr
        openssl x509 -sm3 -req -days 30 -in SE.csr -CA CA.crt -CAkey CA.key -extfile ./openssl.cnf -extensions v3enc_req -out SE.crt -CAcreateserial

        # 生成客户端签名证书和加密证书
        openssl req -config ./openssl.cnf -nodes -subj '/C=AA/ST=BB/O=CC/OU=DD/CN=client sign' -keyout CS.key -newkey ec:SM2.pem -new -out CS.csr
        openssl x509 -sm3 -req -days 30 -in CS.csr -CA CA.crt -CAkey CA.key -extfile ./openssl.cnf -extensions v3_req -out CS.crt -CAcreateserial
        openssl req -config ./openssl.cnf -nodes -subj '/C=AA/ST=BB/O=CC/OU=DD/CN=client enc' -keyout CE.key -newkey ec:SM2.pem -new -out CE.csr
        openssl x509 -sm3 -req -days 30 -in CE.csr -CA CA.crt -CAkey CA.key -extfile ./openssl.cnf -extensions v3enc_req -out CE.crt -CAcreateserial

        export OPENSSL_CONF=`pwd`/../openssl.cnf
        make
        ./ssl_server
        
        # 重新打开一个终端，并进入当前目录
        ./ssl_client
    ```

## OpenSSL SM2测试工具
- 进行OpenSSL SM2算法的加密解密、签名验证，需要版本为OpenSSL-1.1.1x，其中x指任意后缀
- 编译运行
    ```shell
        cd sm2_demo
        export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
        make
        ./sm2_test
    ```

## OpenSSL 功能测试工具
- 需要保证联网或者已经下载好gtest依赖
- 编译运行
    ```shell
        cd func_demo
        sh build.sh

        export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
        cd src
        ./kaedemo

    ```
