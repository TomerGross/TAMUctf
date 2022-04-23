# Offensive Security External CTF Write-up
```
Author: Tomer Gross
CTF name: TAMUctf
Category: Reversing
Challenge name: REdo 3
Final points: 413
```

![01-challenge_desc](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/01-challenge_desc.PNG)

We are given a binary file named `pizza`. Let's start by running the binary. We get no output. Running `strings` CLI tool is not revealing any interesting strings either, also there are no unordinary libraries used in the file. No strings comparison, nothing. Time to hit up our lovely `Ghidra`.

![02-symbol_tree](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/02-symbol_tree.PNG)

Always starting our analysis by checking the `entry` function or in our case `start` function, which simply calls our `main` function.

```c
undefined4 main(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  byte bVar5;
  undefined4 local_9e;
  undefined4 local_9a;
  undefined4 local_96;
  undefined4 local_92;
  undefined2 local_8e;
  undefined4 local_8c [25];
  undefined4 local_28;
  int local_24;
  undefined4 *local_18;
  
  bVar5 = 0;
  local_18 = &param_1;
  if (param_1 == 3) {
    iVar2 = FUN_00011080(*(undefined4 *)(param_2 + 4));
    if (iVar2 == 5) {
      puVar3 = &DAT_00012008;
      puVar4 = local_8c;
      for (iVar2 = 0x19; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar4 = *puVar3;
        puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
        puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
      }
      for (local_24 = 0; local_24 < 100; local_24 = local_24 + 1) {
        *(byte *)((int)local_8c + local_24) =
             *(byte *)((int)local_8c + local_24) ^ *(byte *)(local_24 % 5 + *(int *)(param_2 + 4));
      }
      local_28 = FUN_000110a0(*(undefined4 *)(param_2 + 8));
      local_9e = 0xff7c958d;
      local_9a = 0x458bffff;
      local_96 = 0xffd001e0;
      local_92 = 0xb8d0;
      local_8e = 0;
      (*(code *)&local_9e)();
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

Looks a bit scary, let's analyze part by part. First of all, let's fix our `main` function's signature to the standard signature, int main(int argc, char** argv). That makes clear that our function checks we are feeding it three arguments (including the binary name). Then `argv[1]` and `argv[2]` are the first and second arguments we are feeding the binary.

```c 
iVar1 = FUN_00011080(argv[1]);
```

![03-CALL1](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/03-CALL1.PNG)

There is some function called with our first argument. We have to run the binary with gdb cause static analysis failed us. Remembering our function call address (actually the three last digits `23c` who doesn't change rather of ASLR or PIE), to set a breakpoint. Running gdb with arguments using the command: `gdb --args pizza A B`. 

![04-strlen](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/04-strlen.PNG)

![05-CALL2](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/05-CALL2.PNG)

Our unknown function is actually a simple `strlen` call (which was done over our first argument). Doing the same for our second unknown function reveals that it's just the `atoi` function (done over our second argument). Now that every single command and function call is clear let's delve into analyzing part by part. First, we know we should give two additional arguments in order to enter the if statement. Then running `strlen(argv[1])` reveals that our first argument should be of length 5 in order to enter the next if statement. So far so good, now for the real analysis. From now on assumes the binary fed with two additional arguments, the first one has the length of 5.

```c
puVar3 = &DAT_00012008;
puVar4 = local_8c;
for (iVar2 = 0x19; iVar2 != 0; iVar2 = iVar2 + -1) {
  *puVar4 = *puVar3;
  puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
  puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
}
```

![06-first_loop](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/06-first_loop.PNG)

`puVar3` and `puVar4` are pointers of length 4 bytes, each set with some pointer to memory. The interesting thing here is `DAT_00012008` which points to some data in the binary. Then looping for 25 times, each time copying the data located in `puVar3` to `puVar4` place in memory. Each time we are actually copying 4 bytes, and then incrementing the pointers by 1 but actually, it's better to think of it as incrementing it by 1 place in memory which each time contains 4 bytes. The translation here was a bit confusing though I got it by dynamic analysis but mostly by reading the assembly. The short and best explanation:

![07-rep](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/07-rep.PNG)

To sum up, we copied 100 bytes of data from `DAT_00012008` to the `local_8c` array, which contains 25 elements*4 bytes of data. Then the next thing we need to figure out is the second loop.

![08-second_loop](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/08-second_loop.PNG)

That is quite simple to figure out, each element in our array that we copied data into in our first loop, gets XORed with our first argument's letters, which is used as a repetitive key. Hence, our first element in the array will get XORed with our first letter in the 5 letters key (first argument), the second one with the second letter in the key... The sixth will get XORed with the first letter in the key again, and so on. In the end, we are left with 100 bytes of data, that must contain our key. One more crucial thing we know is the format of the flag which is `gigem{...}`. At this point, we should go back to that `DAT_00012008` place in memory and see whatever key we should set in order to get our flag prefix bytes. So let's extract our data and calculate the key:

![09-data](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/09-data.PNG)

```
g = k0 ^ DAT_00012008[i] --> k0 = g ^ DAT_00012008[i] 
i = k1 ^ DAT_00012008[i+1] --> k1 = i ^ DAT_00012008[i+1]
g = k2 ^ DAT_00012008[i+2] --> k2 = g ^ DAT_00012008[i+2]
e = k3 ^ DAT_00012008[i+3] --> k3 = e ^ DAT_00012008[i+3]
m = k4 ^ DAT_00012008[i+4] --> k4 = m ^ DAT_00012008[i+4] 
```

I wrote this python solver script. The problems were that we don't know exactly where in the 100 bytes of data the flag is located. Since it's possible that the key is not starting in multiples of 5 bytes index, we should not just use "gigem" but also its shifted values: "igemg", "gemgi", "emgig", "mgige", in order to make sure we are not skipping the flag place. So I wrote this brute force script, XORing each key with the data. We get 5 possible outputs back which have to contain our correct key or one of its shifted values. Bruteforcing for all consecutive 5 letters and their shifted values will prompt us with the right key and the flag for the challenge after calculating the output the key gives.

```python
from itertools import cycle
import re

flag_regex = r"gigem\{[^}]+\}"

def find_flag(inp):
    m = re.findall(flag_regex, inp)
    res = re.search(flag_regex, inp)
    if(m != []):
        return m[0], res.start()
    else:
        return None, None

data = "53392421793834082c793e253a103a6a30397e78293f3a2a2f3023a8b0b784acd78248594457f448594456f7c89444574f53e31d574f4858ff574f485dfc574f4847add78248594457f448594456f747c9d4c7dfd8c9d4c7dfd8c9d4c7dfd8c9d4c7dfd8"
data = [int(data[i:i+2], 16) for i in range(0, len(data), 2)][::-1]
flag_perms = [[ord(l) for l in key] for key in ["gigem", "igemg", "gemgi", "emgig", "mgige"]]

for perm in flag_perms:
	pt = "".join([chr(data[i] ^ perm[i%5]) for i in range(len(data))])
	for j in range(0, len(pt)-6):
		p_key = [ord(l) for l in pt[j:j+5]]
		for r in range(5):
			text = "".join([chr(data[i] ^ p_key[(i+r)%5]) for i in range(len(data))])
			flag, inx = find_flag(text)
			if flag:
				print(f"Challenge Solved: {flag}, Key found: {''.join([chr(a) for a in (p_key[r:] + p_key[:r])])}, Position: {inx}")
				exit(0)
```
```
> Challenge Solved: gigem{p01nt3r_mag1c_pa1ns}, Key found: HOWDY, Position: 73
```

We found the flag and at that point, we can put the flag and get the points. However, there are still some missing questions. What is the second parameter do? Since we are still unable to print the flag using just the arguments to the binary, and by putting some different values in the second argument we can see some different behaviors, the second argument must be used in the call address block we have at the end of the program.

![10-last_CALL](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/10-last_CALL.PNG)

Let's run the program using 10 as the second parameter `gdb --args pizza HOWDY 10`.

![12-before_atoi](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/12-before_atoi.PNG)

![11-call_code](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/11-call_code.PNG)

We can see that values are saved into the memory and that we can control the first one, which is our second argument. Then there is a call to address `0xffffcfd2` which is `$ebp-0x96`. 

![13-values_end_call](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/13-values_end_call.PNG)

![14-instructions_end_call](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/14-instructions_end_call.PNG)

We can see that `eax` sets with our second argument value and then added to `edx` base value, then calling the calculated address. `$edx = 0xffffcfe4, $eax = 0x0a`, then our call will be to `0xffffcfee`. Let's print the instructions going on there by using the command `x/25i 0xffffcfee`.

![15-mistery_code](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/15-mistery_code.PNG)

It means that calling that address would be stuck at the bad instruction address `0xffffcff8`. Let's put an offset that will bypass that address. But before we do that, we should mention that we need not only to bypass that address but also the command after that `add    DWORD PTR [eax],eax`, because `$eax = 0xffffcffa` this command overriding the next 4 bytes, which will cause to other bad instructions. So let's jump straight to `0xffffcffc` which will override only the command we have already passed. `0xffffcffc - 0xffffcfe4 = 0x18 = 24`.

Avoiding `add    DWORD PTR [eax],eax`:

![16-2-bad_instruction](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/16-2-bad_instruction.PNG)

We get:

![16-last_last_last](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/16-last_last_last.PNG)

We can notice the instructions: 

```
0xffffd00a:  mov    eax,0x4
0xffffd00f:  mov    ebx,0x1
0xffffd014:  pop    ecx
0xffffd015:  mov    edx,0x1b
0xffffd01a:  int    0x80
```

Which are just doing SYSWRITE of length 27, or in other words, printing something. Surprisingly, `$ecx` gets the value of `0xffffd02d` which stores our flag values!

![17-got_flag](https://github.com/TomerGross/TAMUctf/blob/main/writeup-files/17-got_flag.PNG)

Voilà! We got the flag.

`gigem{p01nt3r_mag1c_pa1ns}`