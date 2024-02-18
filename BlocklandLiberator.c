/**
 * Blockland r2033 Liberator (v1.0)
 *
 * Copyright (C) 2024 Elletra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// ----------------------------------------------------------------

#define BL_REVISION "2033"
#define PROGRAM_VERSION "1.0"

#define U8_SIZE (sizeof(uint8_t))
#define U16_SIZE (sizeof(uint16_t))
#define U32_SIZE (sizeof(uint32_t))

#define SECTION_NAME_LEN 8

// ----------------------------------------------------------------

#define OPEN_FILE(path, mode)\
	FILE *file = fopen(path, mode);\
	if (file == NULL)\
	{\
		error = Open;\
	}\
	else

#define CLOSE_FILE()\
	if (fclose(file) != 0)\
	{\
		error = Close;\
	}

#define READ(field)\
	if (fread(&field, sizeof(field), 1, file) != 1)\
	{\
		return Read;\
	}

#define SKIP(bytes)\
	if (fseek(file, bytes * sizeof(uint8_t), SEEK_CUR))\
	{\
		return Seek;\
	}

#define READ_SECTION(function, ...)\
	error = function(__VA_ARGS__);\
	if (error != None)\
	{\
		CLOSE_FILE()\
		return error;\
	}

#define WRITE_PATCH(rva, count, ...)\
	{\
		uint8_t byte_array[count] = { __VA_ARGS__ };\
		if (fseek(file, rva_to_raw(data, rva), SEEK_SET))\
		{\
			printf("Error: Failed to seek to address 0x%X\n", rva);\
			error = Seek;\
			CLOSE_FILE()\
			return error;\
		}\
		if (fwrite(byte_array, U8_SIZE, count, file) != count)\
		{\
			printf("Error: Failed to write patch at 0x%X\n", rva);\
			error = Write;\
			CLOSE_FILE()\
			return error;\
		}\
	}

// ----------------------------------------------------------------

struct Args
{
	bool display_help;
	bool cli_mode;
	const char *exe_path;
};

const uint32_t PE_OFFSET = 0x3C;
const uint16_t PE32_MAGIC = 0x10B;
const uint16_t DOS_MAGIC = 0x5A4D;
const uint32_t PE_MAGIC = 0x00004550;

const char TEXT_SECTION_NAME[] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };

const int RVA_ENTRY_SIZE = 8;

struct PEData
{
	/* Relevant COFF header data */
	uint16_t num_sections;
	uint16_t optional_header_bytes;

	/* Relevant Windows 32-bit optional header data */
	uint32_t image_base;
	uint32_t num_rvas;

	/* Relevant .text section data */
	uint32_t text_virtual_addr;
	uint32_t text_raw_data_ptr;
};

enum Error
{
	None,
	Arguments,
	Open,
	Close,
	Read,
	Write,
	Seek,
	Unsupported,
	NoDosSig,
	NoPeSig,
	NoPeHeader,
	NoTextSection,
};

const int MIN_ERROR = None;
const int MAX_ERROR = NoTextSection;

const char *error_strings[] =
{
	"No error.",
	"Missing and/or invalid argument(s).",
	"Failed to open file.",
	"Failed to close file.",
	"Failed to read byte(s).",
	"Failed to write byte(s).",
	"Failed to seek to address.",
	"PE32+ files are not supported.",
	"No DOS signature found.",
	"No PE signature found.",
	"No PE header found.",
	"Could not locate a .text section!",
};

// ----------------------------------------------------------------

const char *get_error_string(enum Error error);

uint32_t read_u32(FILE *file);

enum Error read_dos_stub(FILE *file);
enum Error read_pe_sig(FILE *file);
enum Error read_coff_header(FILE *file, struct PEData *data);
enum Error check_optional_header(FILE *file, struct PEData *data);
enum Error read_win_header(FILE *file, struct PEData *data);
enum Error find_text_section(FILE *file, struct PEData *data);

uint32_t rva_to_raw(struct PEData *data, uint32_t rva);

enum Error read_exe(const char *path, struct PEData *data);
enum Error patch_exe(const char *path, struct PEData *data);

void print_header();
void print_help();
void pause(struct Args *args);

bool parse_args(int argc, const char *argv[], struct Args *args);

// ----------------------------------------------------------------

/**
 * WARNING: This program ONLY works properly for Blockland v21 r2033! It DOES NOT check if the
 * executable being patched is the correct version/revision or is even a copy of Blockland. Use at
 * your own risk!
 */

int main(int argc, const char *argv[])
{
	enum Error error = None;

	struct Args args =
	{
		.display_help = false,
		.cli_mode = false,
		.exe_path = NULL,
	};

	print_header();

	if (!parse_args(argc, argv, &args))
	{
		error = Arguments;
		print_help();
	}
	else
	{
		struct PEData data;

		printf("Reading file: \"%s\"\n\n", args.exe_path);

		error = read_exe(args.exe_path, &data);

		if (error == None)
		{
			error = patch_exe(args.exe_path, &data);

			if (error == None)
			{
				printf("\nFile successfully patched!\n\n");
			}
			else
			{
				printf("Error patching executable: %s\n\n", get_error_string(error));
			}
		}
		else
		{
			printf("Error reading executable: %s\n\n", get_error_string(error));
		}
	}

	pause(&args);

	return error;
}

const char *get_error_string(enum Error error)
{
	return (error >= MIN_ERROR && error <= MAX_ERROR) ? error_strings[error] : "";
}

uint32_t read_u32(FILE *file)
{
	uint32_t value = 0;
	fread(&value, U32_SIZE, 1, file);
	return value;
}

enum Error read_dos_stub(FILE *file)
{
	enum Error error = None;

	uint16_t magic;

	READ(magic);

	if (magic != DOS_MAGIC)
	{
		error = NoDosSig;
	}

	return error;
}

enum Error read_pe_sig(FILE *file)
{
	enum Error error = None;

	if (fseek(file, PE_OFFSET, SEEK_SET) || fseek(file, read_u32(file), SEEK_SET))
	{
		error = NoPeSig;
	}
	else
	{
		uint32_t magic;
		int num_read = fread(&magic, sizeof(magic), 1, file);

		if (num_read != 1)
		{
			error = Read;
		}
		else if (magic != PE_MAGIC)
		{
			error = NoPeSig;
		}
	}

	return error;
}

/* Read the COFF header and grab what we need from it. */
enum Error read_coff_header(FILE *file, struct PEData *data)
{
	SKIP(U16_SIZE)
	READ(data->num_sections)
	SKIP(U32_SIZE * 3)
	READ(data->optional_header_bytes)
	SKIP(U16_SIZE)

	return None;
}

/* Check optional header to make sure this is a PE32 and not a PE32+, then skip the rest. */
enum Error check_optional_header(FILE *file, struct PEData *data)
{
	enum Error error = None;

	uint16_t magic;
	READ(magic);

	if (magic != PE32_MAGIC)
	{
		error = Unsupported;
	}
	else
	{
		uint32_t skip = (U8_SIZE * 2) + (U32_SIZE * 6);

		SKIP(skip)

		data->optional_header_bytes -= (sizeof(PE32_MAGIC) + skip);
	}

	return error;
}

enum Error read_win_header(FILE *file, struct PEData *data)
{
	enum Error error = None;

	uint32_t skip = (U32_SIZE * 11) + (U16_SIZE * 8);

	READ(data->image_base)
	SKIP(skip)
	READ(data->num_rvas)

	data->optional_header_bytes -= sizeof(data->image_base) + sizeof(data->num_rvas) + skip;

	SKIP(data->optional_header_bytes)

	return error;
}

enum Error find_text_section(FILE *file, struct PEData *data)
{
	enum Error error = None;

	char name[SECTION_NAME_LEN];

	bool done = false;
	bool is_text = false;

	for (uint16_t i = 0; i < data->num_sections && !done; i++)
	{
		READ(name)
		SKIP(U32_SIZE) // Virtual size

		is_text = !strncmp(name, TEXT_SECTION_NAME, SECTION_NAME_LEN);

		if (is_text)
		{
			READ(data->text_virtual_addr)
		}
		else
		{
			SKIP(U32_SIZE)
		}

		SKIP(U32_SIZE) // Size of raw data

		if (is_text)
		{
			READ(data->text_raw_data_ptr)
		}
		else
		{
			SKIP(U32_SIZE)
		}

		SKIP((U32_SIZE * 3) + (U16_SIZE * 2))

		done = error != None || is_text;
	}

	return !done ? NoTextSection : error;
}

uint32_t rva_to_raw(struct PEData *data, uint32_t rva)
{
	return rva - data->image_base - data->text_virtual_addr + data->text_raw_data_ptr;
}

enum Error read_exe(const char *path, struct PEData *data)
{
	enum Error error = None;

	OPEN_FILE(path, "rb")
	{
		READ_SECTION(read_dos_stub, file)
		READ_SECTION(read_pe_sig, file)
		READ_SECTION(read_coff_header, file, data)

		if (data->optional_header_bytes <= 0)
		{
			error = NoPeHeader;
		}
		else
		{
			READ_SECTION(check_optional_header, file, data)
			READ_SECTION(read_win_header, file, data)
			READ_SECTION(find_text_section, file, data)
		}

		CLOSE_FILE()
	}

	return error;
}

enum Error patch_exe(const char *path, struct PEData *data)
{
	enum Error error = None;

	OPEN_FILE(path, "rb+")
	{
		printf("Removing function definition restrictions...\n");

		/* This is the fewest number of patches I could do without the game crashing. If I studied
		the function more I could probably get it lower, but this is good enough... */

		WRITE_PATCH(0x43035D, 1, 0xEB)
		WRITE_PATCH(0x43037E, 1, 0xEB)
		WRITE_PATCH(0x4303BB, 4, 0xE9, 0x4C, 0x06, 0x00)
		WRITE_PATCH(0x430A16, 5, 0xE9, 0xE9, 0x09, 0x00, 0x00)

		printf("Removing function call restrictions...\n");

		WRITE_PATCH(0x42F3B7, 2, 0xEB, 0x26) // `setMyBLID()`
		WRITE_PATCH(0x42F417, 2, 0xEB, 0x26) // `setDedicatedToken()`
		WRITE_PATCH(0x42F487, 2, 0xEB, 0x26) // `getDedicatedToken()`
		WRITE_PATCH(0x42F517, 2, 0xEB, 0x26) // `setJoinToken()`
		WRITE_PATCH(0x42F587, 2, 0xEB, 0x26) // `getJoinToken()`

		WRITE_PATCH(0x4BAD37, 2, 0xEB, 0x2E) // `GameConnection::setPlayerName()`
		WRITE_PATCH(0x4BAE17, 2, 0xEB, 0x2A) // `GameConnection::setBLID()`
		WRITE_PATCH(0x4BAF57, 2, 0xEB, 0x29) // `GameConnection::getJoinToken()`

		WRITE_PATCH(0x4CA097, 2, 0xEB, 0x2E) // `secureCommandToClient()`
		WRITE_PATCH(0x4CA207, 2, 0xEB, 0x2E) // `secureCommandToAll()`
		WRITE_PATCH(0x4CA3D7, 2, 0xEB, 0x2E) // `secureCommandToAllExcept()`

		WRITE_PATCH(0x59446F, 2, 0xEB, 0x2E) // `NetConnection::connect()`
		WRITE_PATCH(0x594623, 2, 0xEB, 0x2E) // `NetConnection::connectArranged()`

		WRITE_PATCH(0x611F4D, 2, 0xEB, 0x2E) // `SteamGetAuthSessionTicket()`
		WRITE_PATCH(0x612107, 2, 0xEB, 0x2E) // `SteamCancelAuthTicket()`

		printf("Removing function password checks...\n");

		WRITE_PATCH(0x4BAD78, 2, 0xEB, 0x22) // `GameConnection::setPlayerName()`
		WRITE_PATCH(0x4BAE54, 2, 0xEB, 0x26) // `GameConnection::setBLID()`
		WRITE_PATCH(0x4CA107, 2, 0x90, 0x90) // `secureCommandToClient()`
		WRITE_PATCH(0x4CA277, 6, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90) // `secureCommandToAll()`
		WRITE_PATCH(0x4CA447, 6, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90) // `secureCommandToAllExcept()`

		/* `ShapeBase::setShapeName()` */
		WRITE_PATCH(0x4FB0C0, 1, 0x03) // Change argument check amount from 4 to 3
		WRITE_PATCH(0x4FB0C2, 1, 0x8C) // Change comparison from `==` to `>=`
		WRITE_PATCH(0x4FB0C7, 2, 0xEB, 0x1E) // Remove password check

		CLOSE_FILE()
	}

	return error;
}

void print_header()
{
	printf(
		"**************************************\n"
		"*  Blockland r" BL_REVISION " Liberator (v" PROGRAM_VERSION ")  *\n"
		"**************************************\n\n"
	);
}

void print_help()
{
	printf(
		"usage: BlocklandLiberator.exe path [-X] [-h]\n"
		"  options:\n"
		"      -h, --help    Displays help.\n"
		"      -X, --cli     Makes the program operate as a command-line interface\n"
		"                    that takes no keyboard input and closes immediately\n"
		"                    upon completion or failure.\n"
	);
}

void pause(struct Args *args)
{
	if (!args->cli_mode)
	{
		printf("\nPress enter key to continue...\n\n");
		fflush(stdout);
		getchar();	
	}
}

bool parse_args(int argc, const char *argv[], struct Args *args)
{
	bool error = false;

	for (int i = 1; i < argc && !error; i++)
	{
		const char *arg = argv[i];

		if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
		{
			args->display_help = true;
		}
		else if (!strcmp(arg, "-X") || !strcmp(arg, "--cli"))
		{
			args->cli_mode = true;
		}
		else if (arg[0] == '-')
		{
			error = true;
			printf("Unrecognized command-line option '%s'\n\n", arg);
		}
		else if (args->exe_path != NULL)
		{
			error = true;
			printf("Error: Multiple executable files specified.\n\n");
		}
		else
		{
			args->exe_path = arg;
		}
	}

	if (args->exe_path == NULL && !args->display_help)
	{
		error = true;
		printf("Error: No executable file specified.\n\n");
	}

	return !error && !args->display_help;
}
