#!/usr/bin/env python3

keyModification = {}
keyModification[1] = [0] * 16
keyModification[2] = [0xc5,0xb9,0x50,0x88,0xde,0x71,0x6f,0x34,0xcd,0xa4,0x75,0xed,0xa3,0xa4,0xb9,0xd7]
keyModification[3] = [0x47,0x4c,0x6a,0x70,0x8f,0x3d,0x87,0x7c,0x95,0x51,0x9f,0xd5,0xbe,0x3a,0x1b,0xff]
keyModification[4] = [0x32,0xf0,0xc6,0x25,0xfc,0xf2,0x0f,0x1b,0x3b,0x49,0xc4,0x55,0xb9,0x99,0x47,0x0b]
keyModification[5] = [0x0a,0xba,0x43,0x36,0x3a,0xa7,0x0c,0x1f,0x1a,0xc9,0xe5,0x3c,0x30,0xb8,0xb2,0xbc]
keyModification[6] = [0x78, 0x65, 0xb1, 0x14, 0x5d, 0x2b, 0xf6, 0x90, 0x0a, 0xe1, 0x0c, 0xac, 0x4b, 0xb0, 0x39, 0xb1]
keyModification[7] = [0x46, 0x19, 0xe7, 0x3c, 0xe8, 0x9d, 0xd2, 0x27, 0x0a,0xf4,0x30,0x76, 0x3a, 0x24, 0xf7, 0xb1]
keyModification[8] = [0x53, 0x76, 0x47, 0xd8, 0x63, 0xd1, 0xd3, 0xd7, 0xfc, 0x1c, 0xba, 0x89, 0x22, 0xe8, 0x93, 0xb1]
keyModification[9] = [0x67, 0x01, 0xce, 0x60, 0x90, 0x3b, 0x63, 0x27, 0x10, 0x44, 0x49, 0xc3, 0x35, 0xaf, 0xb4, 0x69]
keyModification[10] = [0xd3, 0xba, 0xb5, 0xc5, 0xb0, 0xb0, 0xbf, 0xd8, 0xc6, 0xfc, 0xc6, 0x09, 0x71, 0x8b, 0x9c, 0xfb]
keyModification[11] = [0x68, 0x08, 0xe3, 0x2e, 0x42, 0x00, 0x1d, 0xab, 0x62, 0x27, 0x0a, 0x92, 0xf2, 0x74, 0x29, 0x42]
keyModification[12] = [0x5e, 0x24, 0x86, 0xc5, 0xb5, 0x68, 0xd1, 0xbf, 0x18, 0x0b, 0xa1, 0xee, 0xa7, 0xe3, 0x1c, 0xf4]
# keyModification[13] = [0xce, 0x04, 0x8e, 0x74, 0x24, 0x0b, 0x25, 0xa3, 0x85, 0xbc, 0x2f, 066, 0x7a, 0x3b, 0x64, 0x92]
keyModification[13] = [0xce, 0x04, 0x8e, 0x74, 0x24, 0x0b, 0x25, 0xa3, 0x85, 0xbc, 0x2f, 0x15, 0x7a, 0x3b, 0x64, 0x92]
keyModification[13][6] = 0x66
keyModification[14] = [0x64, 0x8c, 0x97, 0xcd, 0xff, 0x77, 0x1c, 0x8f, 0x0a, 0x7f, 0xa4, 0xb8, 0x4d, 0x6c, 0xc3, 0x50]
FINAL_ROUND = [0xf9, 0xf2, 0xde, 0xf1, 0x64, 0xef, 0xc2, 0x48, 0xb5, 0x59, 0x8e, 0xda, 0xe8, 0x98, 0x17, 0xd3]

# Byte 15
# Key match. Round 13 66, Round 14 50
# Confirmed. Remaining error bytes:
# Candidate found!

# Byte 14
# Key match. Round 13 66, Round 14 c3
# Confirmed. Remaining error bytes:
# Candidate found!

# Byte 13
# Key match. Round 13 66, Round 14 6c
# Confirmed. Remaining error bytes:
# Candidate found!

# Byte 12
# Key match. Round 13 66, Round 14 4d
# Confirmed. Remaining error bytes:
# Candidate found!
