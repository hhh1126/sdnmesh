/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include "qsteer.h"

#define NAME "logic.qtn.sample"
#define PPREFIX "[Logic - "NAME"]: "

#define OUI_LEN 3

static unsigned char block_ouis[] = {
	0x00, 0x03, 0x93,
	0x00, 0x05, 0x02,
	0x00, 0x0A, 0x27,
	0x00, 0x0A, 0x95,
	0x00, 0x0D, 0x93,
	0x00, 0x10, 0xFA,
	0x00, 0x11, 0x24,
	0x00, 0x14, 0x51,
	0x00, 0x16, 0xCB,
	0x00, 0x17, 0xF2,
	0x00, 0x19, 0xE3,
	0x00, 0x1B, 0x63,
	0x00, 0x1C, 0xB3,
	0x00, 0x1D, 0x4F,
	0x00, 0x1E, 0x52,
	0x00, 0x1E, 0xC2,
	0x00, 0x1F, 0x5B,
	0x00, 0x1F, 0xF3,
	0x00, 0x21, 0xE9,
	0x00, 0x22, 0x41,
	0x00, 0x23, 0x12,
	0x00, 0x23, 0x32,
	0x00, 0x23, 0x6C,
	0x00, 0x23, 0xDF,
	0x00, 0x24, 0x36,
	0x00, 0x25, 0x00,
	0x00, 0x25, 0x4B,
	0x00, 0x25, 0xBC,
	0x00, 0x26, 0x08,
	0x00, 0x26, 0x4A,
	0x00, 0x26, 0xB0,
	0x00, 0x26, 0xBB,
	0x00, 0x30, 0x65,
	0x00, 0x3E, 0xE1,
	0x00, 0x50, 0xE4,
	0x00, 0x56, 0xCD,
	0x00, 0x61, 0x71,
	0x00, 0x6D, 0x52,
	0x00, 0x88, 0x65,
	0x00, 0xA0, 0x40,
	0x00, 0xC6, 0x10,
	0x00, 0xCD, 0xFE,
	0x00, 0xF4, 0xB9,
	0x00, 0xF7, 0x6F,
	0x04, 0x0C, 0xCE,
	0x04, 0x15, 0x52,
	0x04, 0x1E, 0x64,
	0x04, 0x26, 0x65,
	0x04, 0x48, 0x9A,
	0x04, 0x4B, 0xED,
	0x04, 0x52, 0xF3,
	0x04, 0x54, 0x53,
	0x04, 0x69, 0xF8,
	0x04, 0xD3, 0xCF,
	0x04, 0xDB, 0x56,
	0x04, 0xE5, 0x36,
	0x04, 0xF1, 0x3E,
	0x04, 0xF7, 0xE4,
	0x08, 0x00, 0x07,
	0x08, 0x66, 0x98,
	0x08, 0x6D, 0x41,
	0x08, 0x70, 0x45,
	0x08, 0x74, 0x02,
	0x0C, 0x15, 0x39,
	0x0C, 0x30, 0x21,
	0x0C, 0x3E, 0x9F,
	0x0C, 0x4D, 0xE9,
	0x0C, 0x51, 0x01,
	0x0C, 0x74, 0xC2,
	0x0C, 0x77, 0x1A,
	0x0C, 0xBC, 0x9F,
	0x0C, 0xD7, 0x46,
	0x10, 0x1C, 0x0C,
	0x10, 0x40, 0xF3,
	0x10, 0x41, 0x7F,
	0x10, 0x93, 0xE9,
	0x10, 0x9A, 0xDD,
	0x10, 0xDD, 0xB1,
	0x14, 0x10, 0x9F,
	0x14, 0x5A, 0x05,
	0x14, 0x8F, 0xC6,
	0x14, 0x99, 0xE2,
	0x18, 0x20, 0x32,
	0x18, 0x34, 0x51,
	0x18, 0x9E, 0xFC,
	0x18, 0xAF, 0x61,
	0x18, 0xAF, 0x8F,
	0x18, 0xE7, 0xF4,
	0x18, 0xEE, 0x69,
	0x18, 0xF6, 0x43,
	0x1C, 0x1A, 0xC0,
	0x1C, 0x5C, 0xF2,
	0x1C, 0x91, 0x48,
	0x1C, 0x9E, 0x46,
	0x1C, 0xAB, 0xA7,
	0x1C, 0xE6, 0x2B,
	0x20, 0x76, 0x8F,
	0x20, 0x78, 0xF0,
	0x20, 0x7D, 0x74,
	0x20, 0x9B, 0xCD,
	0x20, 0xA2, 0xE4,
	0x20, 0xC9, 0xD0,
	0x24, 0x1E, 0xEB,
	0x24, 0x24, 0x0E,
	0x24, 0xA0, 0x74,
	0x24, 0xA2, 0xE1,
	0x24, 0xAB, 0x81,
	0x24, 0xE3, 0x14,
	0x24, 0xF0, 0x94,
	0x28, 0x0B, 0x5C,
	0x28, 0x37, 0x37,
	0x28, 0x5A, 0xEB,
	0x28, 0x6A, 0xB8,
	0x28, 0x6A, 0xBA,
	0x28, 0xA0, 0x2B,
	0x28, 0xCF, 0xDA,
	0x28, 0xCF, 0xE9,
	0x28, 0xE0, 0x2C,
	0x28, 0xE1, 0x4C,
	0x28, 0xE7, 0xCF,
	0x28, 0xED, 0x6A,
	0x28, 0xF0, 0x76,
	0x2C, 0x1F, 0x23,
	0x2C, 0xB4, 0x3A,
	0x2C, 0xBE, 0x08,
	0x2C, 0xF0, 0xA2,
	0x2C, 0xF0, 0xEE,
	0x30, 0x10, 0xE4,
	0x30, 0x63, 0x6B,
	0x30, 0x90, 0xAB,
	0x30, 0xF7, 0xC5,
	0x34, 0x12, 0x98,
	0x34, 0x15, 0x9E,
	0x34, 0x36, 0x3B,
	0x34, 0x51, 0xC9,
	0x34, 0xA3, 0x95,
	0x34, 0xAB, 0x37,
	0x34, 0xC0, 0x59,
	0x34, 0xE2, 0xFD,
	0x38, 0x0F, 0x4A,
	0x38, 0x48, 0x4C,
	0x38, 0x71, 0xDE,
	0x38, 0xB5, 0x4D,
	0x38, 0xC9, 0x86,
	0x38, 0xCA, 0xDA,
	0x3C, 0x07, 0x54,
	0x3C, 0x15, 0xC2,
	0x3C, 0xAB, 0x8E,
	0x3C, 0xD0, 0xF8,
	0x3C, 0xE0, 0x72,
	0x40, 0x30, 0x04,
	0x40, 0x33, 0x1A,
	0x40, 0x3C, 0xFC,
	0x40, 0x6C, 0x8F,
	0x40, 0xA6, 0xD9,
	0x40, 0xB3, 0x95,
	0x40, 0xD3, 0x2D,
	0x44, 0x00, 0x10,
	0x44, 0x2A, 0x60,
	0x44, 0x4C, 0x0C,
	0x44, 0xD8, 0x84,
	0x44, 0xFB, 0x42,
	0x48, 0x3B, 0x38,
	0x48, 0x43, 0x7C,
	0x48, 0x60, 0xBC,
	0x48, 0x74, 0x6E,
	0x48, 0xD7, 0x05,
	0x48, 0xE9, 0xF1,
	0x4C, 0x57, 0xCA,
	0x4C, 0x7C, 0x5F,
	0x4C, 0x8D, 0x79,
	0x4C, 0xB1, 0x99,
	0x50, 0x7A, 0x55,
	0x50, 0xEA, 0xD6,
	0x54, 0x26, 0x96,
	0x54, 0x4E, 0x90,
	0x54, 0x72, 0x4F,
	0x54, 0x9F, 0x13,
	0x54, 0xAE, 0x27,
	0x54, 0xE4, 0x3A,
	0x54, 0xEA, 0xA8,
	0x58, 0x1F, 0xAA,
	0x58, 0x55, 0xCA,
	0x58, 0x7F, 0x57,
	0x58, 0xB0, 0x35,
	0x5C, 0x59, 0x48,
	0x5C, 0x8D, 0x4E,
	0x5C, 0x95, 0xAE,
	0x5C, 0x96, 0x9D,
	0x5C, 0x97, 0xF3,
	0x5C, 0xAD, 0xCF,
	0x5C, 0xF5, 0xDA,
	0x5C, 0xF9, 0x38,
	0x60, 0x03, 0x08,
	0x60, 0x33, 0x4B,
	0x60, 0x69, 0x44,
	0x60, 0x92, 0x17,
	0x60, 0xA3, 0x7D,
	0x60, 0xC5, 0x47,
	0x60, 0xD9, 0xC7,
	0x60, 0xF8, 0x1D,
	0x60, 0xFA, 0xCD,
	0x60, 0xFB, 0x42,
	0x60, 0xFE, 0xC5,
	0x64, 0x20, 0x0C,
	0x64, 0x76, 0xBA,
	0x64, 0x9A, 0xBE,
	0x64, 0xA3, 0xCB,
	0x64, 0xA5, 0xC3,
	0x64, 0xB9, 0xE8,
	0x64, 0xE6, 0x82,
	0x68, 0x09, 0x27,
	0x68, 0x5B, 0x35,
	0x68, 0x64, 0x4B,
	0x68, 0x96, 0x7B,
	0x68, 0x9C, 0x70,
	0x68, 0xA8, 0x6D,
	0x68, 0xAE, 0x20,
	0x68, 0xD9, 0x3C,
	0x68, 0xDB, 0xCA,
	0x68, 0xFB, 0x7E,
	0x6C, 0x3E, 0x6D,
	0x6C, 0x40, 0x08,
	0x6C, 0x70, 0x9F,
	0x6C, 0x72, 0xE7,
	0x6C, 0x8D, 0xC1,
	0x6C, 0x94, 0xF8,
	0x6C, 0xC2, 0x6B,
	0x70, 0x11, 0x24,
	0x70, 0x14, 0xA6,
	0x70, 0x3E, 0xAC,
	0x70, 0x48, 0x0F,
	0x70, 0x56, 0x81,
	0x70, 0x73, 0xCB,
	0x70, 0x81, 0xEB,
	0x70, 0xA2, 0xB3,
	0x70, 0xCD, 0x60,
	0x70, 0xDE, 0xE2,
	0x70, 0xE7, 0x2C,
	0x70, 0xEC, 0xE4,
	0x74, 0x1B, 0xB2,
	0x74, 0x81, 0x14,
	0x74, 0xE1, 0xB6,
	0x74, 0xE2, 0xF5,
	0x78, 0x31, 0xC1,
	0x78, 0x3A, 0x84,
	0x78, 0x6C, 0x1C,
	0x78, 0x7E, 0x61,
	0x78, 0x9F, 0x70,
	0x78, 0xA3, 0xE4,
	0x78, 0xCA, 0x39,
	0x78, 0xD7, 0x5F,
	0x78, 0xFD, 0x94,
	0x7C, 0x01, 0x91,
	0x7C, 0x11, 0xBE,
	0x7C, 0x6D, 0x62,
	0x7C, 0x6D, 0xF8,
	0x7C, 0xC3, 0xA1,
	0x7C, 0xC5, 0x37,
	0x7C, 0xD1, 0xC3,
	0x7C, 0xF0, 0x5F,
	0x7C, 0xFA, 0xDF,
	0x80, 0x00, 0x6E,
	0x80, 0x49, 0x71,
	0x80, 0x92, 0x9F,
	0x80, 0xBE, 0x05,
	0x80, 0xD6, 0x05,
	0x80, 0xE6, 0x50,
	0x80, 0xEA, 0x96,
	0x80, 0xED, 0x2C,
	0x84, 0x29, 0x99,
	0x84, 0x38, 0x35,
	0x84, 0x78, 0x8B,
	0x84, 0x85, 0x06,
	0x84, 0x89, 0xAD,
	0x84, 0x8E, 0x0C,
	0x84, 0xA1, 0x34,
	0x84, 0xB1, 0x53,
	0x84, 0xFC, 0xFE,
	0x88, 0x1F, 0xA1,
	0x88, 0x53, 0x95,
	0x88, 0x63, 0xDF,
	0x88, 0xC6, 0x63,
	0x88, 0xCB, 0x87,
	0x8C, 0x00, 0x6D,
	0x8C, 0x29, 0x37,
	0x8C, 0x2D, 0xAA,
	0x8C, 0x58, 0x77,
	0x8C, 0x7B, 0x9D,
	0x8C, 0x7C, 0x92,
	0x8C, 0x8E, 0xF2,
	0x8C, 0xFA, 0xBA,
	0x90, 0x27, 0xE4,
	0x90, 0x3C, 0x92,
	0x90, 0x60, 0xF1,
	0x90, 0x72, 0x40,
	0x90, 0x84, 0x0D,
	0x90, 0x8D, 0x6C,
	0x90, 0xB0, 0xED,
	0x90, 0xB2, 0x1F,
	0x90, 0xB9, 0x31,
	0x90, 0xC1, 0xC6,
	0x90, 0xFD, 0x61,
	0x94, 0x94, 0x26,
	0x94, 0xE9, 0x6A,
	0x94, 0xF6, 0xA3,
	0x98, 0x01, 0xA7,
	0x98, 0x03, 0xD8,
	0x98, 0x5A, 0xEB,
	0x98, 0xB8, 0xE3,
	0x98, 0xD6, 0xBB,
	0x98, 0xE0, 0xD9,
	0x98, 0xF0, 0xAB,
	0x98, 0xFE, 0x94,
	0x9C, 0x04, 0xEB,
	0x9C, 0x20, 0x7B,
	0x9C, 0x29, 0x3F,
	0x9C, 0x35, 0xEB,
	0x9C, 0x4F, 0xDA,
	0x9C, 0xF3, 0x87,
	0x9C, 0xFC, 0x01,
	0xA0, 0x18, 0x28,
	0xA0, 0x99, 0x9B,
	0xA0, 0xED, 0xCD,
	0xA4, 0x31, 0x35,
	0xA4, 0x5E, 0x60,
	0xA4, 0x67, 0x06,
	0xA4, 0xB1, 0x97,
	0xA4, 0xB8, 0x05,
	0xA4, 0xC3, 0x61,
	0xA4, 0xD1, 0x8C,
	0xA4, 0xD1, 0xD2,
	0xA4, 0xF1, 0xE8,
	0xA8, 0x20, 0x66,
	0xA8, 0x5B, 0x78,
	0xA8, 0x60, 0xB6,
	0xA8, 0x66, 0x7F,
	0xA8, 0x86, 0xDD,
	0xA8, 0x88, 0x08,
	0xA8, 0x8E, 0x24,
	0xA8, 0x96, 0x8A,
	0xA8, 0xBB, 0xCF,
	0xA8, 0xFA, 0xD8,
	0xAC, 0x29, 0x3A,
	0xAC, 0x3C, 0x0B,
	0xAC, 0x61, 0xEA,
	0xAC, 0x7F, 0x3E,
	0xAC, 0x87, 0xA3,
	0xAC, 0xBC, 0x32,
	0xAC, 0xCF, 0x5C,
	0xAC, 0xFD, 0xEC,
	0xB0, 0x34, 0x95,
	0xB0, 0x65, 0xBD,
	0xB0, 0x9F, 0xBA,
	0xB4, 0x18, 0xD1,
	0xB4, 0x4B, 0xD2,
	0xB4, 0x8B, 0x19,
	0xB4, 0xF0, 0xAB,
	0xB8, 0x09, 0x8A,
	0xB8, 0x17, 0xC2,
	0xB8, 0x44, 0xD9,
	0xB8, 0x78, 0x2E,
	0xB8, 0x8D, 0x12,
	0xB8, 0xC7, 0x5D,
	0xB8, 0xE8, 0x56,
	0xB8, 0xF6, 0xB1,
	0xB8, 0xFF, 0x61,
	0xBC, 0x3B, 0xAF,
	0xBC, 0x4C, 0xC4,
	0xBC, 0x52, 0xB7,
	0xBC, 0x54, 0x36,
	0xBC, 0x67, 0x78,
	0xBC, 0x6C, 0x21,
	0xBC, 0x92, 0x6B,
	0xBC, 0xEC, 0x5D,
	0xC0, 0x1A, 0xDA,
	0xC0, 0x63, 0x94,
	0xC0, 0x84, 0x7A,
	0xC0, 0x9F, 0x42,
	0xC0, 0xCC, 0xF8,
	0xC0, 0xCE, 0xCD,
	0xC0, 0xF2, 0xFB,
	0xC4, 0x2C, 0x03,
	0xC4, 0xB3, 0x01,
	0xC8, 0x1E, 0xE7,
	0xC8, 0x2A, 0x14,
	0xC8, 0x33, 0x4B,
	0xC8, 0x69, 0xCD,
	0xC8, 0x6F, 0x1D,
	0xC8, 0x85, 0x50,
	0xC8, 0xB5, 0xB7,
	0xC8, 0xBC, 0xC8,
	0xC8, 0xE0, 0xEB,
	0xC8, 0xF6, 0x50,
	0xCC, 0x08, 0xE0,
	0xCC, 0x20, 0xE8,
	0xCC, 0x25, 0xEF,
	0xCC, 0x29, 0xF5,
	0xCC, 0x44, 0x63,
	0xCC, 0x78, 0x5F,
	0xCC, 0xC7, 0x60,
	0xD0, 0x03, 0x4B,
	0xD0, 0x23, 0xDB,
	0xD0, 0x25, 0x98,
	0xD0, 0x33, 0x11,
	0xD0, 0x4F, 0x7E,
	0xD0, 0xA6, 0x37,
	0xD0, 0xE1, 0x40,
	0xD4, 0x9A, 0x20,
	0xD4, 0xF4, 0x6F,
	0xD8, 0x00, 0x4D,
	0xD8, 0x1D, 0x72,
	0xD8, 0x30, 0x62,
	0xD8, 0x96, 0x95,
	0xD8, 0x9E, 0x3F,
	0xD8, 0xA2, 0x5E,
	0xD8, 0xBB, 0x2C,
	0xD8, 0xCF, 0x9C,
	0xD8, 0xD1, 0xCB,
	0xDC, 0x2B, 0x2A,
	0xDC, 0x2B, 0x61,
	0xDC, 0x37, 0x14,
	0xDC, 0x41, 0x5F,
	0xDC, 0x86, 0xD8,
	0xDC, 0x9B, 0x9C,
	0xE0, 0x5F, 0x45,
	0xE0, 0x66, 0x78,
	0xE0, 0xAC, 0xCB,
	0xE0, 0xB5, 0x2D,
	0xE0, 0xB9, 0xBA,
	0xE0, 0xC7, 0x67,
	0xE0, 0xC9, 0x7A,
	0xE0, 0xF5, 0xC6,
	0xE0, 0xF8, 0x47,
	0xE4, 0x25, 0xE7,
	0xE4, 0x8B, 0x7F,
	0xE4, 0x98, 0xD6,
	0xE4, 0x9A, 0x79,
	0xE4, 0xC6, 0x3D,
	0xE4, 0xCE, 0x8F,
	0xE8, 0x04, 0x0B,
	0xE8, 0x06, 0x88,
	0xE8, 0x80, 0x2E,
	0xE8, 0x8D, 0x28,
	0xE8, 0xB2, 0xAC,
	0xEC, 0x35, 0x86,
	0xEC, 0x85, 0x2F,
	0xEC, 0xAD, 0xB8,
	0xF0, 0x24, 0x75,
	0xF0, 0x99, 0xBF,
	0xF0, 0xB0, 0xE7,
	0xF0, 0xB4, 0x79,
	0xF0, 0xC1, 0xF1,
	0xF0, 0xCB, 0xA1,
	0xF0, 0xD1, 0xA9,
	0xF0, 0xDB, 0xE2,
	0xF0, 0xDB, 0xF8,
	0xF0, 0xDC, 0xE2,
	0xF0, 0xF6, 0x1C,
	0xF4, 0x0F, 0x24,
	0xF4, 0x1B, 0xA1,
	0xF4, 0x31, 0xC3,
	0xF4, 0x37, 0xB7,
	0xF4, 0x5C, 0x89,
	0xF4, 0xF1, 0x5A,
	0xF4, 0xF9, 0x51,
	0xF8, 0x1E, 0xDF,
	0xF8, 0x27, 0x93,
	0xFC, 0x25, 0x3F,
	0xFC, 0xE9, 0x98,
	0xFC, 0xFC, 0x48,

	0xff, 0xff, 0xff
};


struct csm_simple_desc {
	struct csm_plugin_file_desc desc;
	struct csm_logic_plugin *plugin[1];
};

struct csm_simple {
	void *csm_ctx;
};

static void *csm_simple_create_instance(void *csm_ctx)
{
	struct csm_simple *simple = CSM_MALLOC(sizeof(struct csm_simple));
	if (simple) {
		simple->csm_ctx = csm_ctx;
		csm_start_fat_monitor(simple->csm_ctx, 1);
		csm_start_sta_stats_monitor(simple->csm_ctx, 1);
	}
	return simple;
}

static int csm_simple_need_block(unsigned char *mac)
{
	unsigned char *bmac = block_ouis;
	while (*bmac != (unsigned char) 0xff) {
		if (memcmp(bmac, mac, OUI_LEN) == 0)
			return 1;
		bmac += OUI_LEN;
	};
	return 0;
}

static int csm_simple_recv_event(void *ctx, csmmsg_t * event)
{
	struct csm_simple *simple = (struct csm_simple *) ctx;
	csmmsgh_t *h = csm_get_msg_body(event);

	switch (h->id) {
	case EVENT_CONNECT_COMPLETE:
		{
			evt_connect_complete_t *ec =
			    (evt_connect_complete_t *) h;
			if (csm_simple_need_block(ec->sta_mac)) {
				CSM_INFO(PPREFIX "BLOCK %" MACFMT,
					 MACARG(ec->sta_mac));
				Steer_CSM_deauth(simple->csm_ctx, h->bssid, 
						 ec->sta_mac, 5, 1);
			} else {
				CSM_INFO(PPREFIX "ALLOW %" MACFMT,
					 MACARG(ec->sta_mac));
			}

			break;
		}
	default:
		{
			break;
		}
	};
	return 0;
}

static struct csm_logic_plugin simple_csm_logic_plugin = {
	.plugin_head =
	    INIT_PLUGIN_HEAD(NAME, csm_simple_create_instance, NULL, NULL,
			     NULL),
	.type = LOGIC_ROLE_STEERING,
	.ops = {
		.recv_event = csm_simple_recv_event,
		.connect_complete = NULL,
		.bss_trans_status = NULL,
		.register_clbks = NULL,
		},
};

static struct csm_simple_desc g_csm_simple_desc = {
	.desc =
	    INIT_PLUGIN_FILE_DESC(CSM_LOGIC_MAGIC, CSM_LOGIC_VERSION, 1),
	.plugin[0] = &simple_csm_logic_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_csm_simple_desc;
}
