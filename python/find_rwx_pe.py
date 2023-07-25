import os
import pefile
import concurrent.futures
import argparse

def parse_pe_file(file_path):
    ''' Parses PE file from full path and returns a dict containing permissions and size '''
    try:
        pe = pefile.PE(file_path)

        sections = {}

        for section in pe.sections:

            perm_string = 'R' if bool(section.IMAGE_SCN_MEM_READ) else ''
            perm_string += 'W' if bool(section.IMAGE_SCN_MEM_WRITE) else ''
            perm_string += 'X' if bool(section.IMAGE_SCN_MEM_EXECUTE) else ''

            section_info = {
                'permissions': perm_string,
                'size': section.SizeOfRawData,
            }

            sections[section.Name.decode().rstrip("\x00")] = section_info

        return file_path, sections

    except Exception as e:
        # print(f"An error occurred with file {file_path}: {str(e)}")
        return file_path, {}

def scan_directory_for_dlls(dir_path):
    ''' Recursively scans a directory and uses multi-processing to quickly find all DLLs with RWX sections '''
    dll_files = []
    for foldername, subfolders, filenames in os.walk(dir_path):
        for filename in filenames:
            if filename.endswith('.dll'):
                dll_files.append(os.path.join(foldername, filename))

    with concurrent.futures.ProcessPoolExecutor() as executor:
        for dll_path, sections in executor.map(parse_pe_file, dll_files):
            for section, section_info in sections.items():
                if section_info['permissions'] == 'RWX':
                    print(f'DLL: {dll_path}, Section: {section}, Permissions: {section_info["permissions"]}, Size: {section_info["size"]}')

if __name__ == '__main__':

    parser =  argparse.ArgumentParser()
    parser.add_argument('directory', help='Directory path to scan')

    args = parser.parse_args()

    scan_directory_for_dlls(args.directory)
