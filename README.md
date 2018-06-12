# Scanr
Detect x86 shellcode in files and traffic. 

## Usage
```
> python main.py --help
Usage: main.py [-h] [-f OBJ_PATH] [-o START_OFFSET] [-l LIMIT] [-d]
               [-i INTERFACE] [-c CAPTURE]

Windows shellcode emulation and detection tool

optional arguments:
  -h, --help       show this help message and exit
  -f OBJ_PATH      input file
  -o START_OFFSET  shellcode start offset
  -l LIMIT         max instructions to analyze
  -d               enable debug mode
  -i INTERFACE     network interface
  -c CAPTURE       network capture
  ```
Example: `python main.py -c test-http-get.pcap`

## Output
```
python main.py -d -f call4_dword_xor_shell
[!] Starting analysis in file mode
[*] Analyzing file <open file 'call4_dword_xor_shell', mode 'r' at 0x10ed2bdb0>
[+] Found 1 potential offsets:
	0x00000000
  0x0   :	xor	ecx, ecx
  0x2   :	sub	ecx, -0x54
  0x5   :	call	9
  0xa   :	rcr	byte ptr [esi - 0x7f], 0x76
  0xe   :	push	cs
  0xf   :	js	0xfffffff5
  0x11  :	dec	eax
  0x12  :	mov	eax, dword ptr [0xe2fcee83]
  0x17  :	hlt
  0x18  :	test	byte ptr [edx + ecx*8], cl
  0x1b  :	mov	eax, dword ptr [0x2828e478]
  0x20  :	popfd
  0x21  :	aad	0x88
[!] Trying with offset number 0 at 0x00000000
[*] Emulator processing shellcode
  0x2000:	xor	ecx, ecx
  0x2002:	sub	ecx, -0x54
  0x2005:	call	4
  0x2009:	inc	eax
  0x200b:	pop	esi
	mem READ:  0x4, data size = 4, data value = 0x0
	near deref:
		0a 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200c:	xor	dword ptr [esi + 0xe], 0xa148e478
	mem READ:  0x2018, data size = 4, data value = 0x0
	near deref:
		84 0c ca a1 78 e4 28 28 9d d5 88 c5 f3 b4 78 2a
[!] Self-modyfying code heuristic triggered!
  0x2013:	sub	esi, -4
  0x2016:	loop	0xfffffff6
  0x200c:	xor	dword ptr [esi + 0xe], 0xa148e478
	mem READ:  0x201c, data size = 4, data value = 0x0
	near deref:
		78 e4 28 28 9d d5 88 c5 f3 b4 78 2a 2a e8 c3 f3
# skipped..
[!] Self-modyfying code heuristic triggered!
  0x2013:	sub	esi, -4
  0x2016:	loop	0xfffffff6
  0x200c:	xor	dword ptr [esi + 0xe], 0xa148e478
	mem READ:  0x2164, data size = 4, data value = 0x0
	near deref:
		ad e4 48 a1 cc cc cc cc 00 00 00 00 00 00 00 00
[!] Self-modyfying code heuristic triggered!
  0x2013:	sub	esi, -4
  0x2016:	loop	0xfffffff6
  0x2018:	cld
  0x2019:	call	0x87
  0x20a0:	pop	ebp
[!] GetPC (callpop) heuristic triggered!
	mem READ:  0x4, data size = 4, data value = 0x0
	near deref:
		1e 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x20a1:	push	0x3233
  0x20a6:	push	0x5f327377
  0x20ab:	push	esp
  0x20ac:	push	0x726774c
  0x20b1:	call	ebp
  0x201e:	pushal
  0x201f:	mov	ebp, esp
  0x2021:	xor	eax, eax
  0x2023:	mov	edx, dword ptr fs:[eax + 0x30]

[!] PEB accessed!
	mem READ:  0x30, data size = 4, data value = 0x0
	near deref:
		30 00 00 00 00 00 00 00 00 00 00 00 3c 00 00 00
  0x2027:	mov	edx, dword ptr [edx + 0xc]

[!] PEB_Ldr accessed!
[!] HEUR level 3, shellcode detected. Exiting!
	mem READ:  0x3c, data size = 4, data value = 0x0
	near deref:
		3c 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00
[+] Processed!
	Shellcode address ranges:
	   low:  0x2018
	   high: 0x2164

	Decoded shellcode:
  0x0   :	cld
  0x1   :	call	0x88
  0x6   :	pushal
  0x7   :	mov	ebp, esp
  0x9   :	xor	eax, eax
  0xb   :	mov	edx, dword ptr fs:[eax + 0x30]
  0xf   :	mov	edx, dword ptr [edx + 0xc]
  0x12  :	mov	edx, dword ptr [edx + 0x14]
  0x15  :	mov	esi, dword ptr [edx + 0x28]
  0x18  :	movzx	ecx, word ptr [edx + 0x26]
  0x1c  :	xor	edi, edi
  0x1e  :	lodsb	al, byte ptr [esi]
  # skipped..
[+] Finished analysis, took 0.067544 seconds
```
## Dependencies
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
- [Capstone Engine](https://github.com/aquynh/capstone/)
- [Pypcap](https://github.com/pynetwork/pypcap)
