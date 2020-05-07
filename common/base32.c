#include <ctype.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include "mywin32.h"
#endif

#include "base32.h"
#include "dns.h"

/**
 * Let this be a sequence of plain data before encoding:
 *
 *  01234567 01234567 01234567 01234567 01234567
 * +--------+--------+--------+--------+--------+
 * |< 0 >< 1| >< 2 ><|.3 >< 4.|>< 5 ><.|6 >< 7 >|
 * +--------+--------+--------+--------+--------+
 *
 * There are 5 octets of 8 bits each in each sequence.
 * There are 8 blocks of 5 bits each in each sequence.
 *
 * You probably want to refer to that graph when reading the algorithms in this
 * file. We use "octet" instead of "byte" intentionnaly as we really work with
 * 8 bits quantities. This implementation will probably not work properly on
 * systems that don't have exactly 8 bits per (unsigned) char.
 **/


static const unsigned char PADDING_CHAR = '=';

/**
 * Pad the given buffer with len padding characters.
 */
static void pad(unsigned char *buf, int len)
{
	for (int i = 0; i < len; i++)
		buf[i] = PADDING_CHAR;
}

/**
 * This convert a 5 bits value into a base32 character.
 * Only the 5 least significant bits are used.
 */
static unsigned char encode_char(unsigned char c)
{
	static unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	return base32[c & 0x1F];  // 0001 1111
}

/**
 * Decode given character into a 5 bits value.
 * Returns -1 iff the argument given was an invalid base32 character
 * or a padding character.
 */
static int decode_char(unsigned char c)
{
	char retval = -1;

	if (c >= 'A' && c <= 'Z')
		retval = c - 'A';
	if (c >= 'a' && c <= 'z')
		retval = c - 'a';
	if (c >= '2' && c <= '7')
		retval = c - '2' + 26;

	return  retval;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return the index of
 * the octet in which this block starts. For example, given 3 it will return 1
 * because block 3 starts in octet 1:
 *
 * +--------+--------+
 * | ......<|.3 >....|
 * +--------+--------+
 *  octet 1 | octet 2
 */
static int get_octet(int block)
{
	return (block * 5) / 8;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return how many bits
 * we can drop at the end of the octet in which this block starts.
 * For example, given block 0 it will return 3 because there are 3 bits
 * we don't care about at the end:
 *
 *  +--------+-
 *  |< 0 >...|
 *  +--------+-
 *
 * Given block 1, it will return -2 because there
 * are actually two bits missing to have a complete block:
 *
 *  +--------+-
 *  |.....< 1|..
 *  +--------+-
 **/
static int get_offset(int block)
{
	return (8 - 5 - (5 * block) % 8);
}

/**
 * Like "b >> offset" but it will do the right thing with negative offset.
 * We need this as bitwise shifting by a negative offset is undefined
 * behavior.
 */
static unsigned char shift_right(unsigned char byte, char offset)
{
	if (offset > 0)
		return byte >> offset;
	else
		return byte << -offset;
}

static unsigned char shift_left(unsigned char byte, char offset)
{
	return shift_right(byte, -offset);
}

/**
 * Encode a sequence. A sequence is no longer than 5 octets by definition.
 * Thus passing a length greater than 5 to this function is an error. Encoding
 * sequences shorter than 5 octets is supported and padding will be added to the
 * output as per the specification.
 */
static void encode_sequence(const unsigned char *plain, int len, unsigned char *coded)
{
	for (int block = 0; block < 8; block++) {
		int octet = get_octet(block);  // figure out which octet this block starts in
		int junk = get_offset(block);  // how many bits do we drop from this octet?

		
		if (octet >= len) { // we hit the end of the buffer
			pad(&coded[block], 8 - block);
			return;
		}
		

		unsigned char c = shift_right(plain[octet], junk);  // first part

		if (junk < 0  // is there a second part?
			&& octet < len - 1)  // is there still something to read?
		{
			c |= shift_right(plain[octet + 1], 8 + junk);
		}
		coded[block] = encode_char(c);
	}
}

int base32_encode(unsigned char *plain, unsigned char *coded, int len)
{
	// All the hard work is done in encode_sequence(),
	// here we just need to feed it the data sequence by sequence.
	int i = 0, j = 0;
	for (; i < len; i += 5, j += 8) {
		encode_sequence(&plain[i], MIN(len - i, 5), &coded[j]);
	}

	coded[j] = '\0';
	return j;
}

static int decode_sequence(const unsigned char *coded, unsigned char *plain)
{
	plain[0] = 0;
	for (int block = 0; block < 8; block++) {
		int offset = get_offset(block);
		int octet = get_octet(block);

		int c = decode_char(coded[block]);
		if (c < 0)  // invalid char, stop here
			return octet;

		plain[octet] |= shift_left(c, offset);
		if (offset < 0) {  // does this block overflows to next octet?
			plain[octet + 1] = shift_left(c, 8 + offset);
		}
	}
	return 5;
}

int base32_decode(unsigned char *plain, unsigned char *coded)
{
	int written = 0;
	for (int i = 0, j = 0; ; i += 8, j += 5) {
		int n = decode_sequence(&coded[i], &plain[j]);
		written += n;
		if (n < 5)
			return written;
	}
}
