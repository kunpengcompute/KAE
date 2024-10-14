#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "zstd.h"

#define uLong unsigned long

static uLong read_inputFile(const char* fileName, void** input)
{
    FILE* sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    int fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);

    uLong input_size = fs.st_size;
    *input = malloc(input_size);
    if (*input == NULL) {
        return 0;
    }
    (void)fread(*input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
}

static size_t write_outputFile(const char* outFileName, void* output, uLong output_size)
{
    FILE* outputFile = fopen(outFileName, "w");
    if (!outputFile) {
        fprintf(stderr, "%s create failed!\n", outFileName);
        return 0;
    }
    size_t count = fwrite(output, sizeof(char), output_size, outputFile);
    fclose(outputFile);
    return count;
}

#define NAME_TO_STR(name) #name
#define LSTR(x) NAME_TO_STR(x)

int main()
{
	const char* filename = "itemdata";
	printf("filename = %s\n", filename);
	void  *src = NULL;
	size_t src_size = read_inputFile(filename, &src);

	size_t dst_size = src_size;
	void  *dst = malloc(dst_size);

	size_t half_src_size = src_size / 2;
	size_t left_src_size = src_size - half_src_size;
	int isEnd = (left_src_size == 0);

	ZSTD_CStream* cstrm = ZSTD_createCStream();
        ZSTD_initCStream(cstrm, 1);	
	ZSTD_inBuffer  input  = {src, half_src_size, 0};
	ZSTD_outBuffer output = {dst, dst_size, 0};

	/* www */

	printf("Hello ZSTD!\n");
	int a = 1;
	a += 4;

	/* eee */
	size_t total_out_size = 0;	

	size_t size = ZSTD_compressStream(cstrm, &output, &input);
	printf("after ZSTD_compressStream, size = %llu\n", size);
        printf("input.size = %llu, input.pos = %llu\noutput.size = %llu, output.pos = %llu\n\n", input.size, input.pos,
                output.size, output.pos);
	
	if (isEnd && (input.pos == input.size)) {
		size = ZSTD_endStream(cstrm, &output);
		printf("pos == size\nafter ZSTD_endStream, size = %llu\n", size);
	} else {
		getchar();
		size = ZSTD_flushStream(cstrm, &output);
		printf("pos == size\nafter ZSTD_flushStream, size = %llu\n", size);
	}
	printf("input.size = %llu, input.pos = %llu\noutput.size = %llu, output.pos = %llu\n\n", input.size, input.pos,
		output.size, output.pos);
	total_out_size += output.pos;
	getchar();

	if (!isEnd) {
	    input.src += input.pos; input.size = left_src_size; input.pos = 0;
	    output.dst += output.pos; output.size = dst_size - output.pos; output.pos = 0;
	    size = ZSTD_compressStream(cstrm, &output, &input);
	    printf("after ZSTD_compressStream, size = %llu\n", size);
       	    printf("input.size = %llu, input.pos = %llu\noutput.size = %llu, output.pos = %llu\n\n", input.size, input.pos,
                output.size, output.pos);

	    size = ZSTD_endStream(cstrm, &output);
	    printf("after ZSTD_endStream, size = %llu\n", size);
	    printf("input.size = %llu, input.pos = %llu\noutput.size = %llu, output.pos = %llu\n\n", input.size, input.pos,
                output.size, output.pos);
	}	
	total_out_size += output.pos;

	(void)write_outputFile("itemdata1.zst", dst, total_out_size);
	ZSTD_freeCStream(cstrm);
	//解压流程
	
	size_t uncomp_size = src_size + 10000;
	void *uncomp_bytes = malloc(uncomp_size);
	ZSTD_DStream* dstrm = ZSTD_createDStream();

	ZSTD_initDStream(dstrm);

	const size_t block_size = 4096;
	input.src = dst; input.size = 0; input.pos = 0;

	int loop = 1;
	int isReadEnd = 0;
	output.dst = uncomp_bytes; output.size = uncomp_size; output.pos = 0;
	do {
		fprintf(stderr, "loop %d\n", loop++);
		if (loop == 320) {
			fprintf(stderr, "soon failed!\n");
		}
		if (input.pos == input.size) {
			input.src += input.pos;
			int nb;
			if (total_out_size >= block_size) {
				nb = block_size;
			} else {
				nb = total_out_size;
				isReadEnd = 1;
			}
			input.size = nb;
			input.pos  = 0;
			total_out_size -= nb;
			fprintf(stderr, "get new input, size = %llu, left = %llu\n", input.size, total_out_size);

		}

		size_t ret = ZSTD_decompressStream(dstrm, &output, &input);
		fprintf(stderr, "ZSTD_decompressStream return %llu\n", ret);
		fprintf(stderr, "then output.pos = %llu, output.size = %llu\n\n", output.pos, output.size);
		if (ZSTD_isError(ret))
			fprintf(stderr, "zstd decompression failed: %s\n", ZSTD_getErrorName(ret));

		if (ret == 0)
			break;

		if (ret > 0 && isReadEnd && output.pos < output.size)
			fprintf(stderr, "unexpected end of compressed temporary file\n");

	} while (output.pos < output.size);
	
	/*
	size = ZSTD_decompressStream(dstrm, &output, &input);
	*/
        printf("input.size = %llu, input.pos = %llu\noutput.size = %llu, output.pos = %llu\n", input.size, input.pos,
                output.size, output.pos);

        (void)write_outputFile("itemdata.orig", output.dst, output.pos);
 
  	ZSTD_freeDStream(dstrm);
	free(src); free(dst);

	return 0;
}
