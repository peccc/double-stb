## Double free vulnerability in nothings/stb

​	Nothings/stb, an image processing library, has a __double free__ vulnerability in the  __stbi\_\_load_gif_main__ function, stb_image.h  2.28(https://github.com/nothings/stb/blob/master/stb_image.h). This function is called in __stbi_load_gif_from_memory__ and is used to parse files in the gif image format.

### version

​	The affected version of the product Nothings/stb is stb_image.h __2.28__.
### Vulnerability causes

​	The main implementation function of stbi_load_gif_from_memory is stbi__load_gif_main

```c++
static void *stbi__load_gif_main(stbi__context *s, int **delays, int *x, int *y, int *z, int *comp, int req_comp)
{
   if (stbi__gif_test(s)) {
      int layers = 0;
      stbi_uc *u = 0;
      stbi_uc *out = 0;
      stbi_uc *two_back = 0;
      stbi__gif g;
      int stride;
      int out_size = 0;
      int delays_size = 0;

      STBI_NOTUSED(out_size);
      STBI_NOTUSED(delays_size);

      memset(&g, 0, sizeof(g));
      if (delays) {
         *delays = 0;
      }

      do {
         u = stbi__gif_load_next(s, &g, comp, req_comp, two_back);
         if (u == (stbi_uc *) s) u = 0;  // end of animated gif marker

         if (u) {
            *x = g.w;
            *y = g.h;
            ++layers;
            stride = g.w * g.h * 4;

            if (out) {
               void *tmp = (stbi_uc*) STBI_REALLOC_SIZED( out, out_size, layers * stride );
               if (!tmp)
                  return stbi__load_gif_main_outofmem(&g, out, delays);
               else {
                   out = (stbi_uc*) tmp;
                   out_size = layers * stride;
               }

               if (delays) {
                  int *new_delays = (int*) STBI_REALLOC_SIZED( *delays, delays_size, sizeof(int) * layers );
                  if (!new_delays)
                     return stbi__load_gif_main_outofmem(&g, out, delays);
                  *delays = new_delays;
                  delays_size = layers * sizeof(int);
               }
            } else {
               out = (stbi_uc*)stbi__malloc( layers * stride );
               if (!out)
                  return stbi__load_gif_main_outofmem(&g, out, delays);
               out_size = layers * stride;
               if (delays) {
                  *delays = (int*) stbi__malloc( layers * sizeof(int) );
                  if (!*delays)
                     return stbi__load_gif_main_outofmem(&g, out, delays);
                  delays_size = layers * sizeof(int);
               }
            }
            memcpy( out + ((layers - 1) * stride), u, stride );
            if (layers >= 2) {
               two_back = out - 2 * stride;
            }

            if (delays) {
               (*delays)[layers - 1U] = g.delay;
            }
         }
      } while (u != 0);

      // free temp buffer;
      STBI_FREE(g.out);
      STBI_FREE(g.history);
      STBI_FREE(g.background);

      // do the final conversion after loading everything;
      if (req_comp && req_comp != 4)
         out = stbi__convert_format(out, 4, req_comp, layers * g.w, g.h);

      *z = layers;
      return out;
   } else {
      return stbi__errpuc("not GIF", "Image was not as a gif type.");
   }
}
```

When stride*layer = 0, for example g.w,g.h or layer is 0, such a situation would arise. 

```c++
*tmp = (stbi_uc*) STBI_REALLOC_SIZED( out, out_size, layers * stride );
```

When out_size = 0, this function is equivalent to free, the "__out__" pointer is freed at this point.

In this function, the "__out__" pointer is released a second time.

```c++
static void *stbi__load_gif_main_outofmem(stbi__gif *g, stbi_uc *out, int **delays)
{
   STBI_FREE(g->out);
   STBI_FREE(g->history);
   STBI_FREE(g->background);

   if (out) STBI_FREE(out);
   if (delays && *delays) STBI_FREE(*delays);
   return stbi__errpuc("outofmem", "Out of memory");
}
```

### Vulnerability reproduce

​	After glibc 2.28, a check for double free was implemented, which in such cases can cause the program to crash. A program using this function is shown here as an example.

​	The environment is shown below.

![image-20230913154142754](https://github.com/peccc/double-stb/blob/master/image/1.png)

​	In the "double_example" folder, use the following command.

```shell
./build.sh
```

​	or

```shell
./example sample
```

![image-20230919175413413](https://github.com/peccc/double-stb/blob/master/image/2.png)

​	We can see the "core dumped".

### Impact

​	Denial of service attack, program crashes after tcache detection.

​	Other possible impacts, for example, In specific circumstances, this may lead to further exploitation such as code execution.

​	The first time it is freed, realloc's size is 0.

![image-20230913154810441](https://github.com/peccc/double-stb/blob/master/image/3.png)

​	For the second free, the free function frees the pointer again.

![image-20230913154940588](https://github.com/peccc/double-stb/blob/master/image/4.png)

​	

