# File Structure Oriented Programming (FSOP)

<div class="hidden">
    keywords: fsop, pwn, aaw, aar, arbitrary address write, arbitrary address read, primitive
</div>

```admonish note
Some lines of code are hidden for brevity.

When hovering over the code block, press the eye button on the top right corner
to toggle the hidden lines.
```


## Built-in File Struct

### `struct _IO_FILE`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/bits/types/struct_FILE.h#L49>

```c,hidelines=//
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

//  /* The following fields are used to support backing up and undo. */
//  char *_IO_save_base; /* Pointer to start of non-current get area. */
//  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
//  char *_IO_save_end; /* Pointer to end of non-current get area. */
//
//  struct _IO_marker *_markers;
//
  struct _IO_FILE *_chain;

  int _fileno;
//  int _flags2;
//  __off_t _old_offset; /* This used to be _offset but it's too small.  */

//  /* 1+column number of pbase(); 0 is unknown. */
//  unsigned short _cur_column;
  signed char _vtable_offset;
//  char _shortbuf[1];

  _IO_lock_t *_lock;
//#ifdef _IO_USE_OLD_IO_FILE
};
```

#### _flags

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libio.h#L66>

```c
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```

### `struct _IO_FILE_plus`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L325>

```c
typedef struct _IO_FILE FILE;

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

Usage on glibc stdio

```c
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
```

#### `struct _IO_jump_t`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L294>

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

## Arbitrary Address Write

- Human language:
    - the ability to write anywhere on the memory
    - read file content then write to memory (`fread`)
    - reading data **into** memory
- `C` language:
    - `read(fd, buf, size);`
    - `fread(buf, size, nmemb, fp)`

Requirements:
- `_flags & _IO_NO_READS (0x4) == 0`[^no-read]
- `_IO_read_ptr == _IO_read_end`
- `_IO_buf_base` is set to the starting address to write into
- `_IO_buf_end` is set to the end address (starting address + number of bytes to be written into)

Example using [`pwntools`](https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer)
to setup for writing `nb` number of bytes into address `target_address`

```py,hidelines=~
from pwn import *

~target_address = 0x1337
~nb = 0x100
fs = FileStructure()
# flags taken from unbuffered _IO_2_1_stdin_, but most importantly 0xfbad208b & _IO_NO_READS == 0
fs.flags = 0xfbad208b
fs._IO_buf_base = target_address
fs._IO_buf_end = target_address + nb
payload = bytes(fs)

# Alternative way
payload = FileStructure().read(addr=target_address, size=nb)
```

[^no-read]: Default for `fopen(filepath, "r")` or achievable by `_flag & (~_IO_NO_READS)`

## Arbitrary Address Read

- Human language:
    - the ability to read any data from memory
    - read from memory then write to file (`fwrite`)
    - reading data **from** memory
- `C` language:
    - `write(fd, buf, size);`
    - `fwrite(buf, size, nmemb, fp)`

Requirements:
- `_flags & _IO_NO_WRITES (0x8) == 0`[^no-write]
- `_flags & _IO_UNBUFFERED (0x2) == 1` (not necessary, but desirable in most cases)
- `_IO_read_end == _IO_write_base`
- `_IO_write_base` is set to the starting address to read from
- `_IO_write_ptr` is set to the end address (starting address + number of bytes to be read from)

Example using [`pwntools`](https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer)
to setup for reading `nb` number of bytes from address `target_address`

```py,hidelines=~
from pwn import *

~target_address = 0x1337
~nb = 0x100
fs = FileStructure()
# flags taken from unbuffered _IO_2_1_stdout_, but most importantly 0xfbad2887 & _IO_NO_WRITES == 0
fs.flags = 0xfbad2887
fs._IO_write_base = target_address
fs._IO_write_ptr = target_address + nb
payload = bytes(fs)

# Alternative way
payload = FileStructure().write(addr=target_address, size=nb)
```

[^no-write]: Default for `fopen(filepath, "w")` or achievable by `_flag & (~_IO_NO_WRITES)` (`_IO_NO_WRITES = 0x8`)


## References

- <https://pwn.college/software-exploitation/file-struct-exploits>
- <https://github.com/un1c0rn-the-pwnie/FSOPAgain>
- <https://faraz.faith/2020-10-13-FSOP-lazynote/>
- <https://niftic.ca/posts/fsop/#known-exploitation-techniques>
- <https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer>
