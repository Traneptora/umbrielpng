# umbrielpng
PNG chunk analyzer and modifier

```
$ gcc -Wall -o ./umbrielpng umbrielpng.c -lz
$ ./umbrielpng --help
Usage: ./umbrielpng [options] [--] <png...>
Options:
    -v, --verbose
        Be verbose. Specify twice to be extra verbose.
    --fix-in-place, -o <output>, --o=<output>
        Fix the PNG file. --fix-in-place works in place, otherwise use the provided output.
    --cicp-prim=<primaries>
    --cicp-trc=<transfer>
        Tag the output file with a cICP chunk with the provided primaries and transfer.
    --srgb
        Equivalent to --cicp-prim=bt709 --cicp-trc=srgb
```
