# PFD/SFO tools
flatz's pdf/sfo tools

## pfdtool v0.2.3

```
pfdtool 0.2.3 (c) 2012 by flatz

USAGE: pfdtool [options] command

COMMANDS       Parameters              Explanation
 -h, --help                            Print this help
 -l, --list    dir                     List entries
 -c, --check   dir                     Verify a database
 -u, --update  dir                     Update an existing database
 -e, --encrypt dir files...            Encrypt specified files and update a database
 -d, --decrypt dir files...            Decrypt specified files and update a database
 -b, --brute   dir elf offset files... Bruteforce a secure file IDs for specified files

OPTIONS        Parameters              Explanation
 -g, --game    product-code            Use a specified game setting set
 -p, --partial                         Don't update/verify all hashes
 -a, --advance                         The offset to advance each time while bruteforcing
 ```
 
 ## sfopatcher v0.1.0
 
 ```
 sfopatcher 0.1.0 (c) 2012 by flatz

USAGE: sfopatcher command [options]
COMMANDS Parameters         Explanation
 build   in tpl out         Build a new <out> using an existing <in> and <tpl> as a template
   --copy-title             Copy TITLE/SUB_TITLE parameters too
   --copy-detail            Copy DETAIL parameter too
 patch   in out             Patch an existing <in> and save it to <out>
   --remove-copy-protection Remove a copy protected flag

 -h, --help                 Print this help
 -v, --verbose              Enable verbose output
 ```
