.intel_syntax noprefix
.text

.global toolbox_start, toolbox_end, store_png_start, store_png_size, toolbox_lite_start, toolbox_lite_end

toolbox_start:
.incbin "assets/etaHEN_toolbox.sxml"
toolbox_end:

.type   store_png_start, @object
.align  16
store_png_start:
   .incbin "assets/store.png"
store_png_end:
.global store_png_size
	.type   store_png_size, @object
	.align  4
store_png_size:
    .int    store_png_end - store_png_start


toolbox_lite_start:
.incbin "assets/etaHEN_Lite.sxml"
toolbox_lite_end:

