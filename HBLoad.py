import idaapi
import idc
import pefile
import os
import struct
from collections import namedtuple

DLL_BASEPATH = "C:\\Windows\\System32\\"

HBHEADER_SIZE = 0x18
HBHEADER_MAGIC = 0x10000301
HBHEADER_FIELDS = "magic dll_list iat ep mod_size relocs_size relocs"
HBHEADER_FMT = '<lhhllll'
HBHeader = namedtuple("HBHeader", HBHEADER_FIELDS)
HBSEGNAME = "HIDDEN.B"
NETNODE_NAME = '$ HBLdrData'

####################################################################
#                    BASIC UTILITY STUFF                           #
####################################################################

# Read a DWORD from a particular location. Return a tuple with:
# * a boolean, whether the read was successful
# * an integer, the DWORD read if successful
def dwordAt(li, off):
	li.seek(off)
	s = li.read(4)
	if len(s) < 4:
		return (False,0)
	return (True,struct.unpack('<I', s)[0])

# Read a WORD from a particular location. Return a tuple with:
# * a boolean, whether the read was successful
# * an integer, the WORD read if successful
def wordAt(li, off):
	li.seek(off)
	s = li.read(2)
	if len(s) < 2:
		return (False,0)
	return (True,struct.unpack('<H', s)[0])

# Read multiple DWORDs; return a list of them only if every read succeeded
def dwordsAt(li, off, num):
	dwOpts = map(lambda o: dwordAt(li,off+o*4), xrange(num))
	if all( e[0] for e in dwOpts ):
		return map(lambda e: e[1], dwOpts)

####################################################################
#                    API/HASHING FUNCTIONS                         #
####################################################################

# The hash algorithm used in Hidden Bee's import by hash
def HiddenBeeHash(name):
	hash = 0x1505
	for c in map(ord, name):
		hash = (c+(hash*33))&0xffffffff
	return hash
	
# Given the name of a DLL and a function to use to hash its export names, 
# return a dictionary mapping the hashed names to the plaintext names.
def HashExportNames(dllName, hashfunc=HiddenBeeHash):
	# Open the PE file and create the IDC file
	pe = pefile.PE(DLL_BASEPATH+dllName, fast_load=False) 
	
	hashtable = dict()
	
	# Create an enum element for each exported name
	for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols: 
		if entry.name != None:
			hashtable[hashfunc(entry.name)] = entry.name		

	return hashtable

# Given:
# * dll, a string naming a DLL
# * iatCurr, the current position within 
# * hashes, a list of DWORDs
#
# Load the DLL with pefile, hash its export names, create a dictionary with
# that information, then look up each hash in the dictionary and if found,
# rename the database location to the corresponding import's name.
def do_dll_imports(dll, iatCurr, hashes):
	idaapi.msg("%lx: processing import hashes for dll %s\n" % (iatCurr, dll))
	hash2name = HashExportNames(dll)
	for h in hashes:
		if h in hash2name:
			idaapi.create_dword(iatCurr, 4)
			idaapi.set_name(iatCurr, hash2name[h], idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)
		else:
			idaapi.msg("%lx: hash value %lx for dll %s could not be found\n" % iatCurr, h, dll)
		iatCurr += 4			
	
####################################################################
#                      RELOCATION-RELATED                          #
####################################################################

# This is the logic I reverse engineered out of IDA's built in PE loader
# module, pe.dll. Don't ask me to explain it beyond that.
def do_reloc(ea, differential):
	fd = idaapi.fixup_data_t(idaapi.FIXUP_OFF32)
	dest = idaapi.get_dword(ea)
	fd.off = dest
	if differential != 0:
		fd.off += differential
		idaapi.set_dword(ea, dest+differential)
	dseg = idaapi.getseg(dest)
	if dseg is not None:
		fd.sel = dseg.sel
		fd.off -= idaapi.sel2para(dseg.sel)*16
	idaapi.set_fixup(ea, fd)

# Apply the above function en masse to all relocations
def do_relocs(relocs, currentBase, newBase):
	idaapi.msg("[I] Processing relocations\n" % ea)
	for reloc in relocs:
		do_reloc(reloc, newBase-currentBase)

####################################################################
#              LOADER MODULE INTERFACE FUNCTIONS                   #
####################################################################

# Determine whether or not the header seems like a Hidden Bee image. I do some
# basic sanity checking on the header values here, which is not strictly 
# necessary. You could choose to continue parsing the file to the best of your
# ability even if some of these conditions failed.
def accept_file(li, filename):
	# Parse the header
	li.seek(0)
	rawData = li.read(HBHEADER_SIZE)
	if len(rawData) < HBHEADER_SIZE:
		return 0
  	
	head = HBHeader._make(struct.unpack(HBHEADER_FMT, rawData))
  	
	if (head.magic != HBHEADER_MAGIC):
		return 0
	
	if head.dll_list > head.mod_size:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (dll_list %#x outside module boundary %#x)\n" % (head.dll_list,head.mod_size))
		return 0

	if head.iat > head.mod_size:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (iat %#x outside module boundary %#x)\n" % (head.iat,head.mod_size))
		return 0

	if head.ep > head.mod_size:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (entrypoint %#x outside module boundary %#x)\n" % (head.er,head.mod_size))
		return 0

	if head.relocs > head.mod_size:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (relocations table %#x outside module boundary %#x)\n" % (head.er,head.mod_size))
		return 0

	if head.relocs_size & 3 != 0:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (relocations size %d not a multiple of 4)\n" % head.relocs_size)
		return 0
	
	if head.relocs + head.relocs_size > head.mod_size:
		idaapi.msg("[E] Hidden Bee Loader: header seems corrupt (relocations table end %#x is outside of module boundary %#x)\n" % (head.relocs + head.relocs_size,head.mod_size))
		return 0

	return {"format": "Hidden Bee Custom Format", "processor": "metapc", "options":1|idaapi.ACCEPT_FIRST}	

# Once the previous function has returned successfully, we know we have 
# something that we can try to parse as a Hidden Bee image and load it into 
# IDA.
def load_file(li, neflags, format):
	# Not clear why this is necessary given the return value from accept_file, 
	# but IDA will quit if you don't include this.
	idaapi.set_processor_type("metapc", idaapi.SETPROC_LOADER)
	
	# This boolean will be set if IDA is "reloading" the file as opposed to 
	# loading it for the first time, i.e., File->Load File->Reload Input File.
	# We just ignore requests to reload.
	bReload = (neflags & idaapi.NEF_RELOAD) != 0
	if bReload:
		return 1

	# Parse the header again
	li.seek(0)
	rawData = li.read(HBHEADER_SIZE)
	head = HBHeader._make(struct.unpack(HBHEADER_FMT, rawData))
  
	# Add a code segment
	seg = idaapi.segment_t()
	seg.start_ea = 0
	seg.end_ea = head.mod_size
	seg.bitness = 1
	idaapi.add_segm_ex(seg, HBSEGNAME, "CODE", 0)
  
	# Read the contents of the file into the code segment we just created
	li.seek(0)
	li.file2base(0,0,head.mod_size,False)				

	# Create data items for the header fields and give them names
	idaapi.create_dword(0x00, 4)
	idaapi.set_name(0x00, "HBHDR_Magic", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_word(0x04, 2)
	idaapi.set_name(0x04, "HBHDR_DllList", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_word(0x06, 2)
	idaapi.set_name(0x06, "HBHDR_IAT", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_dword(0x08, 4)
	idaapi.set_name(0x08, "HBHDR_EntryPoint", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_dword(0x0C, 4)
	idaapi.set_name(0x0C, "HBHDR_ModuleSize", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_dword(0x10, 4)
	idaapi.set_name(0x10, "HBHDR_RelocationsSize", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	idaapi.create_dword(0x14, 4)
	idaapi.set_name(0x14, "HBHDR_Relocations", idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_NOCHECK)

	# Add the module's entrypoint as an entrypoint in IDA
	idaapi.add_entry(head.ep, head.ep, "start", 1)
	
	# Load a type library so that the imports will show proper names and types.
	# I'm not sure why idaapi.load_til doesn't do what I want, but it doesn't.
	idc.LoadTil("mssdk_win7")

	# Parse the import table in a loop.
	dllEntryPos = head.dll_list
	iatCurr = head.iat
	dllNumFuncsOpt = wordAt(li,dllEntryPos)
	
	# For each DLL entry, where the DLL entry list is terminated by an entry 
	# specifying zero imports...
	while dllNumFuncsOpt[0] and dllNumFuncsOpt[1] != 0:
		if dllNumFuncsOpt[1] * 4 + head.iat > head.mod_size:
			idaapi.msg("[E] Hidden Bee Loader: IAT entry outside of module boundary %#x. Aborting import parsing.\n" % (dllNumFuncsOpt[1], head.mod_size))
			break
  
		# Get the DLL name
		dllName = li.getz(idaapi.MAXSTR, dllEntryPos + 2)		
		
		# Get the specified number of DWORD hashes
		hashes = dwordsAt(li, iatCurr, dllNumFuncsOpt[1])
		if hashes is None:
			idaapi.msg("[E] Hidden Bee Loader: could not read %d API hashes beginning at %#x. Aborting import parsing.\n" % (dllNumFuncsOpt[1], iatCurr))
			break
		
		# Look up the hashes, rename their addresses after the corresponding API
		do_dll_imports(dllName, iatCurr, hashes)
  
		# Move on to next DLL
		iatCurr += 4 * dllNumFuncsOpt[1]
		dllEntryPos += 2 + len(dllName) + 1
		dllNumFuncsOpt = wordAt(li,dllEntryPos)
  
	# Check that the last DLL entry read correctly
	if not dllNumFuncsOpt[0]:
		idaapi.msg("[E] Hidden Bee Loader: could not read IAT DLL entry at %#x. Aborting import parsing.\n" % dllEntryPos)
  
	# Read the relocations
	relocs = dwordsAt(li, head.relocs, head.relocs_size/4)
	if not relocs:
		idaapi.msg("[E] Hidden Bee Loader: could not read relocation data. Aborting relocation parsing.\n")
		return 1
  
	idaapi.msg("[I] Processing relocations\n")
	for reloc in relocs:
		if reloc > head.mod_size:
			idaapi.msg("[E] Hidden Bee Loader: relocation entry %#x outside of module boundary %#x, skipping.\n" % (reloc, head.mod_size))
		else:
			do_reloc(reloc, 0)
  
	# Store a copy of the relocation data in a global netnode in case the user 
	# messes with it in the database. Needed so we can relocate the database if
	# the user requests it.
	gNode = idaapi.netnode()
	gNode.create(NETNODE_NAME)
	gNode.setblob(idaapi.get_bytes(head.relocs, head.relocs_size), 0, 'D')
		
	return 1			

# Relocate the database from address 'frm' to address 'to'.
def move_segm(frm, to, sz, fileformatname):
	idaapi.msg("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
	
	gNode = idaapi.netnode()
	gNode.create(NETNODE_NAME)
	dBlob = gNode.getblob(0, 'D')
	dwords = [ struct.unpack_from("<l", dBlob, x) for x in xrange(0, len(dBlob), 4) ]
	do_relocs(dwords, frm, to)
	
	return 1
