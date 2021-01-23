# AG-OMP
A parallel attack graph generator based on C and OpenMP

## Description

This is a parallel attack graph generator based on C and OpenMP. It takes a network model and its exploit patterns as input and generates an attack graph instance, which includes a node array and an edge array. The output instance can be used for further analysis.

## System requirement

- 8 GB memory (to run with large input data)
- CentOS, Debian and Ubuntu
- gcc compiler

## Files

- main.c: the C file with main function
- ag_gen.c: the C file with parallel attack graph generator function
- compile.sh: the shell script to compile the program
- run.sh: the shell script to run the program
- *.data: input data files. Each describes a network model and its exploit patterns

## How to use the code

1. Clone this repo to your system, then run `compile.sh`:

```
$ ./compile.sh
```

2. Open `run.sh` with a text editor and set program execution parameters. An example setting:

```
./app numThreads 4 initQSize 480 filename chain_small.data
```

Here, `4` OpenMP threads are set. The `initQSize 480` sets 480 initial nodes for these OpenMP threads to start with. The network model and its exploit patterns are read in from the input file `chain_small.data`. 

Based on the configuration of your system, you may choose a setting different from the example. Please note that you should always set `initQSize >= numThreads`, which ensures every thread has at least one node to expand. 

3. Run `run.sh`:

```
$ ./run.sh
```

A successful execution based on the above example setting will print the following information:

```
...
--->>> The number of nodes in the attach graph is 797161
--->>> The number of edges in the attack graph is 6643012
--->>> The attack graph generation took xx.xxxxxx seconds
>>>>>>>>>>>>>>>>> Step 5: done
```

## Recommended approaches to analyze the generated attack graph:

- store the node and edge arrays into a database
- import the attack graph into Python or R for visualization and data analysis

## Technical support

- Please read this [paper](https://ieeexplore.ieee.org/abstract/document/8855310) for the design details of our parallel attack graph generator
- Please contact mingfinkli@gmail.com if you have further questions
