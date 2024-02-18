# Blockland r2033 Liberator (v1.0)

This program patches out certain restrictions from a Blockland v21 r2033 executable.

## Game Restrictions

### Function definition restrictions

Certain functions (like `WebCom_PostServer()` and `fxDTSBrick::willCauseChainKill()`) cannot be overwritten in vanilla Blockland. This program removes those.

### Function call restrictions

Certain functions (like `setMyBLID()` and `GameConnection::setPlayerName()`) cannot be called in vanilla Blockland except from certain `.dso` files. This program removes those.


### Function password checks

Certain functions (like `secureCommandToClient()` and `ShapeBase::setShapeName()`) have password arguments required to call them in vanilla Blockland. This program removes the checks, but ***does not*** change the arguments of the functions themselves!

For example, the first argument of `secureCommandToClient()` is the function password `zbR4HmJcSY8hdRhr`.

You do not have to call `secureCommandToClient("zbR4HmJcSY8hdRhr", %client, ...);` but you still have to put *something* there.

Instead, you can just leave it blank: `secureCommandToClient("", %client, ...);`

However, `ShapeBase::setShapeName()` is the **lone exception** to this. This is because the password is the *last* argument, rather than the *first*. This program makes this last password argument **optional**.

You do not have to call `%player.setShapeName("My New Name", 8564862);`

Instead, you can just call `%player.setShapeName("My New Name");`

## Usage

This program ***only*** works properly for Blockland v21 r2033! It ***does not*** check if the executable being patched is the correct version/revision or is even a copy of Blockland. ***Use at your own risk!***

There are two ways to use this program: either as a typical console program, or as a command-line interface.

To use it normally, just drag an executable onto the program. Make sure it's a copy of Blockland v21 r2033!

***

You can also use it as a command-line program: `BlocklandLiberator.exe path [-X] [-h]`

`-h` or `--help` displays help.

`-X` or `--cli` makes the program behave as a command-line interface. Since the vast majority of users of this program will use Windows, it operates as a normal program by default, pausing after errors and certain messages. This option disables that and will simply display error/success messages and then immediately exit.

## Building

I wrote this as a single-file C program to make it as easy as possible to build. If you can't figure it out yourself, download a pre-built binary.
