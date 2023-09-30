#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#define STBI_ONLY_GIF
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

void read_file_to_buffer(char *file_name, unsigned char **file_buf, long *file_size)
{
	FILE *fp = fopen (file_name, "rb");
	if (!fp){
		printf("File \"%s\" not found!", file_name);
		exit(0);
	}

	fseek(fp, 0L, SEEK_END);
	*file_size = ftell(fp);
	fseek(fp, 0L ,SEEK_SET);
	printf("Filename \"%s\", file_size %lu", file_name, *file_size);

	*file_buf = malloc(*file_size);
	if (*file_buf == NULL){
		printf("Not enough memory!");
		exit(0);
	}

	if (fread(*file_buf, sizeof(char), *file_size, fp) != *file_size)
		printf("fread() error while reading \"%s\"!", file_name);

	fclose(fp);
}


int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s filename.gif\n", argv[0]);
		exit(1);
	}

	char *img_filename;
	unsigned char *img_file_buf = NULL;
	long img_file_buf_len;
	int img_w, img_h, img_channels, img_frames;
	unsigned char *img_fb;

	img_filename = argv[1];

	read_file_to_buffer(img_filename, &img_file_buf, &img_file_buf_len);

	//int* a = NULL;
	//*a = 1;  
	img_fb = stbi_load_gif_from_memory(img_file_buf, img_file_buf_len, NULL, &img_w, &img_h, &img_frames, &img_channels, 4);
	//img_fb = stbi_load_from_memory(img_file_buf, img_file_buf_len, &img_w, &img_h,  &img_channels, 4);

	if (img_fb == NULL){
		printf("File \"%s\" not found, not correct or not a gif!", img_filename);
		exit(0);
	}

	free(img_file_buf);
	stbi_image_free(img_fb);

	return 0;
}
