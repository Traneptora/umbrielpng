# umbrielpng
PNG chunk analyzer and modifier

```
$ gcc -o ./umbrielpng umbrielpng.c -lz
$ ./umbrielpng --help
Usage: ./umbrielpng [-v | --verbose] [options] [--] <png...>
Options:
    --fix-in-place | -o <output> | --o=<output>
        Fix the PNG file. --fix-in-place works in place, otherwise use the provided output.
    --cicp-prim=<primaries>
    --cicp-trc=<transfer>
        Tag the output file with a cICP chunk with the provided primaries and transfer.
```
