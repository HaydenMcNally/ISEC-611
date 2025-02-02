# ISEC-611
 Garbled Circuits Project


This is a code example demonstrating how garbled circuits work.

The example consists of two participants: the Garbler (the other program) and the Evaluator (this program).
The Garbler creates the circuit and 'garbles' all the inputs (encrypts them), then sends them to the Evaluator.
The Evaluator processes the garbled circuits to obtain the final result.

We begin in the Garbler with the makeCircuit function. The logic circuit being created consists of:

Gate 1: AND  
Gate 2: OR  
Gate 3: XOR  
The outputs of Gate 1 and Gate 2 feed into Gate 3.

## Requirements:
The only external library needed to run the program is cryptography, which can be installed with:

`pip install cryptography`


## Running the Programs:
First, start the Garbler by running:

`python .\garbler.py`

Once the Garbler is running, start the Evaluator with:

`python .\evaluator.py`
