#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

extern "C" {
#include "aes.h"
#include "keys.h"
}

#define STATE_SIZE 4
#define NUM_ROUNDS 4


typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct u128
{
	u8 buffer[16];
};

static_assert(sizeof(u8) == 1, "incorrect u8 size");
static_assert(sizeof(u16) == 2, "incorrect u16 size");
static_assert(sizeof(u32) == 4, "incorrect u32 size");
static_assert(sizeof(u128) == 16, "incorrect u128 size");

#define SWAP(x) ((x >> 24) & 0xff | (x >> 8) & 0xff00 | (x << 8) & 0xff0000 | (x << 24) & 0xff000000)

u32 calcCrc32(const void* buffer, u32 len)
{
	const u8* message = (const u8*)buffer;
	int i, j;
	u32 byte, crc, mask;

	i = 0;
	crc = 0xFFFFFFFF;
	while (len--)
	{
		byte = message[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--)
		{
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i = i + 1;
	}
	return ~crc;
}

struct SavePartitionHeader
{
	u32 formatVersion;
	u16 saveVersion;
	u16 flags;
	u32 crc32;
	u32 magic;

	void setCrc32(const u32 sz)
	{
		crc32 = calcCrc32((const u8*)&formatVersion + sizeof(*this), sz);
	}
};

struct CryptInfo
{
	u32 rand32(u128& value) const
	{
		u32* rand = (u32*)&value;

		u32 t = rand[0];
		t ^= (t << 11);
		t ^= (t >> 8);
		t ^= rand[3];
		t ^= (rand[3] >> 19);

		rand[0] = rand[1];
		rand[1] = rand[2];
		rand[2] = rand[3];
		rand[3] = t;
		return t;
	}

	const u128 randkey(u128& keyState, u32* lut) const
	{
		u32 key32[4];
		memset(&key32, 0, sizeof(key32));

		for (u32 i = 0; i < 4; i++)
		{
			for (u32 j = 0; j < 4; j++)
			{
				u32 state = key32[i];

				u32 lookup = lut[rand32(keyState) >> 26];

				u32 t = (rand32(keyState) >> 27) & 0x18;

				t = lookup >> t;
				state |= (t & 0xFF);


				if (j != 3)
				{
					state = state << 8;
				}

				key32[i] = state;
			}
		}
		return reinterpret_cast<const u128&>(key32);
	}

	u128 iv;
	u128 rand;
	u128 mac;
};

static_assert(sizeof(CryptInfo) == 0x30, "incorrect CryptInfo size");

struct mm_file_type
{
	char* name;
	char* fileName;
	size_t fileSize;
	size_t offset;
	uint32_t* key_table;
};

void rand_init(uint32_t *rand_state, const u128& in)
{
	const u32* in32 = (const u32*)&in;
	int cond = in32[0] | in32[1] | in32[2] | in32[3];
	
	rand_state[0] = cond ? in32[0] : 1;
	rand_state[1] = cond ? in32[1] : 0x6C078967;	
	rand_state[2] = cond ? in32[2] : 0x714ACB41;
	rand_state[3] = cond ? in32[3] : 0x48077044;
}

uint32_t rand_gen(uint32_t *rand_state)
{	
	uint32_t n = rand_state[0] ^ rand_state[0] << 11;
	rand_state[0] = rand_state[1];
	n ^= n >> 8 ^ rand_state[3] ^ rand_state[3] >> 19;
	rand_state[1] = rand_state[2];
	rand_state[2] = rand_state[3];
	rand_state[3] = n;
	return n;
}

void gen_key(uint32_t *key_table, uint32_t *out_key, uint32_t *rand_state)
{
	out_key[0] = 0;
	
	for (int i = 0; i < STATE_SIZE; i++)
	{		
		for (int j = 0; j < NUM_ROUNDS; j++)
		{
			out_key[i] <<= 8;
			out_key[i] |= (key_table[rand_gen(rand_state) >> 26] >> ((rand_gen(rand_state) >> 27) & 24)) & 0xFF;
		}
	}
}

int usage(int argc, char **argv)
{
	printf("Usage: %s input output\nflag -h preserves header, required to re-encrypt later.\nflag -e encrypt\n", argv[0]);
	return -1;
}

char endsWith(const char* a, const char* b)
{
	if (!a || !b)
	{
		return 0;
	}

	int lenA = strlen(a);
	int lenB = strlen(b);

	if (lenB > lenA)
	{
		return 0;
	}

	return strcmp(a + lenA - lenB, b) == 0;
}

struct mm_file_type file_types[] = {
	{ "save", "save.dat", 0xC000, 0x0, save_key_table },
	{ "quest", "quest.dat", 0xC000, 0x0, quest_key_table },
	{ "later", "later.dat", 0xC000, 0x0, later_key_table },
	{ "replay", ".dat", 0x68000, 0x0, replay_key_table },
	{ "network", "network.dat", 0x48000, 0x0, network_key_table },
	{ "thumb", ".btl", 0x1C000, 0x0, thumb_key_table },
	{ "course", ".bcd", 0x5C000, sizeof(SavePartitionHeader), course_key_table }
};

struct mm_file_type* getFileType(const char* fileName, size_t size)
{
	for (int i = 0; i < sizeof(file_types) / sizeof(struct mm_file_type); i++)
	{
		if (file_types[i].fileSize == size && endsWith(fileName, file_types[i].fileName))
		{
			return &file_types[i];
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	bool preserveHeader = false;
	bool encrypt = false;
	char* inFileName = NULL;
	char* outFileName = NULL;

	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'e':
				encrypt = true;
				break;
			case 'h':
				preserveHeader = true;
				break;
			default:
				return usage(argc, argv);
			}
		}
		else if(!inFileName)
		{
			inFileName = argv[i];
		}
		else if (!outFileName)
		{
			outFileName = argv[i];
		}
		else
		{
			return usage(argc, argv);
		}
	}

	if (!inFileName || !outFileName)
	{
		return usage(argc, argv);
	}
	
	FILE *in = fopen(inFileName, "rb");
	FILE *out = fopen(outFileName, "wb");
	
	fseek(in, 0, SEEK_END);
	size_t sz = ftell(in);
	rewind(in);
	
	struct AES_ctx ctx;
	
	uint32_t rand_state[STATE_SIZE];
	uint32_t key_state[STATE_SIZE];


	struct mm_file_type* file_type = getFileType(inFileName, sz);

	if (!file_type)
	{
		if (encrypt)
		{
			printf("unsupported file: %s, did you forget to preserve headers?\n", inFileName);
		}
		else
		{
			printf("unsupported file: %s\n", inFileName);
		}
		return -1;
	}

	auto *buf = (u8*)malloc(file_type->fileSize);
	memset(buf, 0, file_type->fileSize);

	fread(buf, 1, file_type->fileSize, in);
	fclose(in);


	u8* end = buf + sz - sizeof(CryptInfo);
	CryptInfo cryptInfo = *(CryptInfo*)(buf + sz - sizeof(CryptInfo));

	rand_init(rand_state, cryptInfo.rand);
	gen_key(file_type->key_table, key_state, rand_state);

	AES_init_ctx_iv(&ctx, (uint8_t *)key_state, end);	

	u32 bodyLen = sz - (sizeof(CryptInfo) + file_type->offset);
	u8* body = buf + file_type->offset;


	if (encrypt)
	{
		if (file_type->offset)
		{
			auto header = (SavePartitionHeader*)buf;
			header->setCrc32(bodyLen);
		}
		printf("Encrypting %s %s to %s...\n", file_type->name, inFileName, outFileName);
		AES_CBC_encrypt_buffer(&ctx, body, bodyLen);
		fwrite(buf, 1, sz, out);
	}
	else
	{
		

		printf("Decrypting %s %s to %s...\n", file_type->name, inFileName, outFileName);
		AES_CBC_decrypt_buffer(&ctx, body, bodyLen);

		if (preserveHeader)
		{
			fwrite(buf, 1, sz, out);
		}
		else
		{
			fwrite(body, 1, bodyLen, out);
		}
	}
	
	fclose(out);

	free(buf);
	
	puts("Done!");
	
	return 0;
}