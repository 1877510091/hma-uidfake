// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the ABX reader: the sample is the first 64 bytes of a real
 * /data/system/packages.xml (Android 17), so what is checked here is the actual
 * format and not a description of it.
 *
 * 41 42 58 00        "ABX\0", the magic every ABX file starts with
 * 10                 START_DOCUMENT | TYPE_NULL
 * 32 ff ff 00 08 …   START_TAG | STRING_INTERNED, a new interned string "packages"
 * 32 ff ff 00 07 …   START_TAG, "version"
 * 6f ff ff 00 0a …   ATTRIBUTE | TYPE_INT, name "sdkVersion", value 0x25 = 37
 * 6f …               the next attribute, whose name is cut off by the sample
 */
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <vector>

#include "abx.hpp"

namespace
{

const std::uint8_t kSample[] = {
	0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0xff, 0xff, 0x00, 0x08, 'p',
	'a',  'c',  'k',  'a',	'g',  'e',  's',  0x32, 0xff, 0xff, 0x00,
	0x07, 'v',  'e',  'r',	's',  'i',  'o',  'n',	0x6f, 0xff, 0xff,
	0x00, 0x0a, 's',  'd',	'k',  'V',  'e',  'r',	's',  'i',  'o',
	'n',  0x00, 0x00, 0x00, 0x25, 0x6f, 0xff, 0xff, 0x00, 0x0e, 's',
	'd',  'k',  'V',  'e',	'r',  's',  'i',  'o',	'n'
};

int failures;

void expect(bool ok, const char *what)
{
	if (!ok) {
		std::printf("FAIL: %s\n", what);
		++failures;
	}
}

void test_sample()
{
	uidfake::abx::Reader reader{ kSample };
	auto event = reader.next();

	expect(event.kind == uidfake::abx::Reader::Event::Kind::StartTag,
	       "first event is a start tag");
	expect(event.name == "packages", "the root tag is packages");

	event = reader.next();
	expect(event.kind == uidfake::abx::Reader::Event::Kind::StartTag,
	       "second event is a start tag");
	expect(event.name == "version", "and it is <version>");

	event = reader.next();
	expect(event.kind == uidfake::abx::Reader::Event::Kind::Attribute,
	       "third event is an attribute");
	expect(event.name == "sdkVersion", "named sdkVersion");
	expect(event.numeric && event.number == 37,
	       "and carries the integer 37");

	expect(!reader.failed(), "the sample is read without an error");
}

void test_bad_input()
{
	const std::uint8_t not_abx[] = { '<', '?', 'x', 'm', 'l' };
	uidfake::abx::Reader wrong{ not_abx };
	expect(wrong.next().kind == uidfake::abx::Reader::Event::Kind::Bad,
	       "a file that is not ABX is refused");

	/* 0x0b is event code 11: the format defines 0..10 and 15, so this one really
	 * is unknown, unlike 0x55 which is a CDATA section. */
	const std::uint8_t unknown_token[] = { 0x41, 0x42, 0x58, 0x00, 0x0b };
	uidfake::abx::Reader unknown{ unknown_token };
	expect(unknown.next().kind == uidfake::abx::Reader::Event::Kind::Bad,
	       "an unknown event byte is refused");

	const std::uint8_t truncated[] = { 0x41, 0x42, 0x58, 0x00, 0x32,
					   0xff, 0xff, 0x00, 0x08, 'p',
					   'a',	 'c',  'k' };
	uidfake::abx::Reader cut{ truncated };
	(void)cut.next();
	expect(cut.failed(),
	       "a truncated string is an error, not a half-read name");
}

/*
 * A comment is part of the format, and a writer that leaves one in must not cost
 * the device all of its rules: the sample with one comment in front of it has to
 * read exactly the same.
 */
void test_comment_is_skipped()
{
	std::vector<std::uint8_t> bytes{ 0x41, 0x42, 0x58, 0x00 };

	/* COMMENT | TYPE_STRING, then one plain string: length, then bytes. */
	bytes.push_back(0x29);
	bytes.insert(bytes.end(), { 0x00, 0x03, 'h', 'i', 0x00 });
	bytes.insert(bytes.end(), std::begin(kSample) + 4, std::end(kSample));

	uidfake::abx::Reader reader{ bytes };
	const auto event = reader.next();

	expect(event.kind == uidfake::abx::Reader::Event::Kind::StartTag &&
		       event.name == "packages",
	       "a document with a comment in front still reads");
	expect(!reader.failed(), "and the reader is not in a failed state");
}

} // namespace

int main()
{
	test_sample();
	test_comment_is_skipped();
	test_bad_input();
	if (failures == 0)
		std::printf("abx reader: PASS\n");
	return failures == 0 ? 0 : 1;
}
