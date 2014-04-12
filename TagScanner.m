/*
 Battle.net Tag Scanner Proof of Concept
 Created by: Samuel Marshall

 Contact: me@samdmarshall.com
 Twitter: @Dirk_Gently
 
 How it works:
 This code is designed to scan through Diablo III's memory and look for user chat identifiers. Once found, these can be used to locate fully
 formed Battle.net Tags which are stored in plain text in memory. This proof of concept only shows how to grab these tags from idling in
 a chat channel. The actual details this reveals is that full Battle.net tags are stored in memory as plaintext in a specific format that could 
 be searched for quite easily. Across multiple days and instance of running Diablo III I found this following format in common:
 
 	[ 80 00 00 00 ] [ XX XX XX XX ] [ YY YY YY YY ] [ Battle.net tag string (this is null terminated) ]
 
 	* In all cases the header of [ 80 00 00 00 ] is used, 
 
 	* Between launches the [ XX XX XX XX ] set of bytes changes, some cases have this be [ 00 00 00 00 ] AND another set of bytes, but both 
 	  will consistantly match up with other tags. So far only seems to be zeros or a set of 4 bytes. Either way both are used and make finding
 	  full Battle.net tags a very easy process.
 
 	* The next set of bytes [ YY YY YY YY ] I didn't try to decipher, but it seemed to change between tags, so possibly a unique identifier for 
 	  the tag.
 
 	* Lastly was a plain text string that contained the full Battle.net tag as a null-terminated c-string.

 This proof of concept for collecting Battle.net tags involves scanning chat channels for users. This will only pick up users that are
 mentioned in a chat channel or have a clickable link to their profile displayed in the chat box. For example, if one where to join a 
 general chat channel prior to running this tool, and were to execute a '/who' in that channel, all the tags of the people currently 
 in that channel will be collected by this tool.


	Copyright (c) 2013, Sam Marshall
	All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
	1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
	3. All advertising materials mentioning features or use of this software must display the following acknowledgement:
	This product includes software developed by the Sam Marshall.
	4. Neither the name of the Sam Marshall nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY Sam Marshall ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Sam Marshall BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	
 */

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#import <stdint.h>
#import <mach/std_types.h>
#import <mach/mach_traps.h>
#import <signal.h>
#import <mach/mach_init.h>
#import <mach/vm_map.h>
#import <mach/mach_vm.h>
#import <mach/mach.h>

@interface NSArray (NSArrayAdditions)
typedef BOOL (^zg_array_filter_t)(id item);
typedef NSComparisonResult (^zg_binary_search_t)(id __unsafe_unretained currentObject);
- (NSArray *)zgFilterUsingBlock:(zg_array_filter_t)shouldFilter;
@end

@implementation NSArray (NSArrayAdditions)
- (NSArray *)zgFilterUsingBlock:(zg_array_filter_t)shouldFilter {
	NSMutableArray *newResults = [[NSMutableArray new] autorelease];
	for (id item in self) {
		if (!shouldFilter(item))
			[newResults addObject:item];
	}
	return [NSArray arrayWithArray:newResults];
}
@end

struct SearchData {
	mach_vm_size_t dataSize;
	mach_vm_size_t dataAlignment;
	void *searchValue;
	mach_vm_address_t beginAddress;
	mach_vm_address_t endAddress;
};

struct MemoryRegion {
	mach_vm_address_t address;
	mach_vm_size_t size;
	vm_prot_t protection;
};

struct TagName {
	mach_vm_address_t nameAddress;
	mach_vm_size_t nameLength;
	vm_map_t task;
};

typedef struct TagName (^search_for_data_t)(struct SearchData *searchData, void *variableData, void *compareData, mach_vm_address_t address);

NSArray *MemoryRegionsForProcess(vm_map_t task) { // returns array of all memory regions for a task
	NSMutableArray *regions = [[NSMutableArray new] autorelease];
	mach_vm_address_t address = 0x0;
	mach_vm_size_t size;
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objectName = MACH_PORT_NULL;
	while (mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount, &objectName) == KERN_SUCCESS) {
		struct MemoryRegion *region = malloc(sizeof(struct MemoryRegion));
		region->address = address;
		region->size = size;
		region->protection = info.protection;
		[regions addObject:[NSValue value:region withObjCType:@encode(struct MemoryRegion)]];
		address += size;
	}
	return [NSArray arrayWithArray:regions];
}

BOOL ReadBytes(vm_map_t task, mach_vm_address_t address, void **bytes, mach_vm_size_t *size) { // wrapper for reading bytes from memory, returns YES or NO depending on success.
	mach_vm_size_t originalSize = *size;
	vm_offset_t dataPointer = 0;
	mach_msg_type_number_t dataSize = 0;
	if (mach_vm_read(task, address, originalSize, &dataPointer, &dataSize) == KERN_SUCCESS) {
		*bytes = (void *)dataPointer;
		*size = dataSize;
		return YES;
	}
	return NO;
}

mach_vm_size_t LengthUntilString(vm_map_t task, mach_vm_address_t address, char *find, size_t stringLen) { // from a given memory address, find the next occurance of a string, then return distance from memory address to that string
	mach_vm_size_t length = 0;
	mach_vm_size_t charSize = sizeof(char);
	mach_vm_size_t stringLength = stringLen;
	void *buffer = NULL;
	while (YES) {
		BOOL canReadBytes = ReadBytes(task, address, &buffer, &stringLength);
		if (canReadBytes) {
			if (strncmp(((char *)buffer), find, stringLength) == 0)
				break;
			length += charSize;
		} else {
			break;
		}
		mach_vm_deallocate(current_task(), (vm_offset_t)buffer, stringLength);
		address += charSize;
	}
	return length;
}

mach_vm_size_t FindStringSize(vm_map_t processTask, mach_vm_address_t address, mach_vm_size_t oldSize) { // from a given memory address, find c-string's length and return it
	mach_vm_size_t totalSize = 0;
	mach_vm_size_t characterSize = sizeof(char);
	void *buffer = NULL;
	BOOL shouldUseOldSize = (oldSize >= characterSize);
	BOOL couldReadBytes = YES;
	while (couldReadBytes) {
		mach_vm_size_t outputtedSize = shouldUseOldSize ? oldSize : characterSize;
		couldReadBytes = ReadBytes(processTask, address, &buffer, &outputtedSize);
		if (couldReadBytes) {
			mach_vm_size_t numberOfCharacters = outputtedSize / characterSize;
			for (mach_vm_size_t characterCounter = 0; characterCounter < numberOfCharacters; characterCounter++) {
				if (((char *)buffer)[characterCounter] == 0) {
					couldReadBytes = NO;
					break;
				}
				totalSize += characterSize;
			}
		}
		mach_vm_deallocate(current_task(), (vm_offset_t)buffer, outputtedSize);
		if (couldReadBytes)
			address += outputtedSize;
	}
	return totalSize;
}

void *valueFromString(NSString *stringValue, mach_vm_size_t *dataSize) { // converts a given string into a pointer, used for memory searching
	void *value = NULL;
	const char *variableValue = [stringValue cStringUsingEncoding:NSUTF8StringEncoding];
	*dataSize = strlen(variableValue);
	value = malloc((size_t)*dataSize);
	strncpy(value, variableValue, (size_t)*dataSize);
	return value;
}

void SearchForData(vm_map_t processTask, struct SearchData *searchData, NSMutableArray *potentialbattleTags, NSMutableArray *battleTags, search_for_data_t searchForDataBlock) {
	mach_vm_size_t dataAlignment = searchData->dataAlignment;
	mach_vm_size_t dataSize = searchData->dataSize;
	void *searchValue = searchData->searchValue;	
	mach_vm_address_t dataBeginAddress = searchData->beginAddress;
	mach_vm_address_t dataEndAddress = searchData->endAddress;
	NSArray *regions = [MemoryRegionsForProcess(processTask) zgFilterUsingBlock:(zg_array_filter_t)^(NSValue *regionValue) {
		struct MemoryRegion region;
		[regionValue getValue:&region];
		return !(region.address < dataEndAddress && region.address + region.size > dataBeginAddress && region.protection & VM_PROT_READ && region.protection & VM_PROT_WRITE);
	}]; // ensuring that all the regions are valid before the search begins
	dispatch_group_t group = dispatch_group_create();
	dispatch_apply(regions.count, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(size_t regionIndex) { // iterating over each region of memory, this is asynchronous so all regions are being checked at the same time
		struct MemoryRegion region;
		[[regions objectAtIndex:regionIndex] getValue:&region];
		mach_vm_address_t address = region.address;
		mach_vm_size_t size = region.size;
		char *bytes = NULL;
		if (ReadBytes(processTask, address, (void **)&bytes, &size)) {
			mach_vm_size_t dataIndex = 0;
			while (dataIndex + dataSize <= size) {
				if (dataBeginAddress <= address + dataIndex && dataEndAddress >= address + dataIndex + dataSize) {
					struct TagName result = searchForDataBlock(searchData, &bytes[dataIndex], searchValue, address + dataIndex);
					if (result.nameLength != 0) { // if the callback produced a zero length tag, then ignore and continue searching gracefully
						dispatch_group_async(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{ // fire off a async thread for processing a new full memory search for the potential tag that was just found.
							char *bytes = NULL;
							if (ReadBytes(result.task, result.nameAddress, (void **)&bytes, (mach_vm_size_t *)&result.nameLength)) { // reading bytes from memory to retrieve the tag name found
								search_for_data_t searchForFullTagBlock = ^(struct SearchData *searchData, void *variableData, void *compareData, mach_vm_address_t address) {
									if ((strncmp(variableData, compareData, (size_t)searchData->dataSize) == 0)) { // checking to make sure that the partial tag matches the string found in memory
										mach_vm_size_t tagLength = FindStringSize(result.task, address, 0); // finding the string size for this tag, when battletags are stored in memory they seem to be followed by a null character (they are c-strings) find this string's length. Results show that not all battle tags have 4 numeric digits in them, some have 5, cannot assume to be a specific length
										char *bytes = NULL;
										if (ReadBytes(result.task, address, (void **)&bytes, &tagLength)) { // reading full battle tag from memory
											if (bytes && strlen(bytes) && tagLength != searchData->dataSize) {
												NSString *tag = [NSString stringWithCString:bytes encoding:NSUTF8StringEncoding]; // read the c-string
												NSArray *tagTest = [tag componentsSeparatedByString:@"#"]; // separate by the hash, setting up for tag parsing
												if (tagTest.count == 2) { // there should only be two results if the string read is a battle.net tag
													uint32_t identifier = 0;
													NSScanner *identifierScanner = [NSScanner scannerWithString:[tagTest objectAtIndex:1]]; // setting up parsing for getting the unique ID
													[identifierScanner scanInt:(int*)&identifier]; // some unique IDs are 5 digits instead of 4, and some cases found strings of data that contained the battle.net tag, but wasn't a proper instance storage of it.
													tag = [[tagTest objectAtIndex:0] stringByAppendingFormat:@"#%i",identifier]; // reading in the unique ID
													NSPredicate *tagPredicate = [NSPredicate predicateWithFormat:@"SELF contains %@",tag]; // setting up for filtering against already found tags
													NSArray *filterResults = [battleTags filteredArrayUsingPredicate:tagPredicate]; // filtering against known tags, it should only print each tag once
													if (!filterResults.count) { // found a new tag!
														[battleTags addObject:tag]; // add to the array of found battle.net tags
														NSLog(@"%@",tag); // since a new tag was found, print this to console!
													}
												}
											}
										}
										mach_vm_deallocate(current_task(), (vm_offset_t)bytes, tagLength); // freeing bytes used for reading a full tag
									}
									return (struct TagName){0x0, 0, result.task}; // end searching gracefully, regardless if a tag was found or not, the search must move on.
								};
								mach_vm_size_t length = 0;
								NSString *potentialTag = [NSString stringWithCString:bytes encoding:NSUTF8StringEncoding]; // reading the tag
								potentialTag = [potentialTag stringByTrimmingCharactersInSet:[NSCharacterSet symbolCharacterSet]]; // stripping out invalid character sets from the tag
								potentialTag = [potentialTag stringByTrimmingCharactersInSet:[NSCharacterSet punctuationCharacterSet]]; // stripping out more invalid character sets
								if (potentialTag.length >= 3 && potentialTag.length <= 12) { // verifying that the tag is within the battle.net tag specification for length
									potentialTag = [potentialTag stringByAppendingFormat:@"#"]; // adding the hash to start looking for the plaintext tag
									NSPredicate *tagPredicate = [NSPredicate predicateWithFormat:@"SELF contains %@",potentialTag]; // setting up tag filtering
									NSArray *filterResults = [potentialbattleTags filteredArrayUsingPredicate:tagPredicate]; // make sure a search is not already happening for this tag
									if (filterResults.count == 0 && potentialTag) { // this is a new tag
										[potentialbattleTags addObject:potentialTag]; // add it to the potential tags pool
										struct SearchData *tagSearch = calloc(1, sizeof(struct SearchData)); // creating search parameters for finding the full battle tag
										tagSearch->searchValue = valueFromString(potentialTag, &length); 
										tagSearch->dataSize = length;
										tagSearch->dataAlignment = sizeof(int8_t);
										tagSearch->beginAddress = 0x0;
										tagSearch->endAddress = ((mach_vm_address_t)MACH_VM_MAX_ADDRESS);
										SearchForData(result.task, tagSearch, potentialbattleTags, battleTags, searchForFullTagBlock); // executing search to find what seems to be a tag name
										free(tagSearch); // freeing memory used by search parameters on the tag name
									}
								}
							}
						});
					}
				}
				dataIndex += dataAlignment; // moving on in the region search
			}
			mach_vm_deallocate(current_task(), (vm_offset_t)bytes, size); // freeing the memory used for reading the tag name
		}
	});
	dispatch_group_wait(group, DISPATCH_TIME_FOREVER); // waiting on all spawned searches to finish before exiting the program
	dispatch_release(group); // releasing the dispatch group
}

int main (int argc, const char * argv[]) {
	//testingTaskForPid();
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	NSMutableArray *battleTags = [[NSMutableArray new] autorelease];
	NSMutableArray *potentialbattleTags = [[NSMutableArray new] autorelease];
	NSArray *diablo3Instances = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.blizzard.diablo3"]; // Checking if there is an instance of Diablo 3 currently running
	if (diablo3Instances.count) { // At least one instance has been found
		for (NSRunningApplication *instance in diablo3Instances) { // iterating over all instance of Diablo 3, this should only ever be one instance
			pid_t process = [instance processIdentifier]; // getting the process identifier from the instance of the running application
			vm_map_t task;
			kern_return_t result = task_for_pid(current_task(), process, &task); // acquiring task for application instance
			if (result != KERN_SUCCESS) {
				if (task != MACH_PORT_NULL)
					mach_port_deallocate(mach_task_self(), task);
				task = MACH_PORT_NULL;
				NSLog(@"Failed to get task for process %d: %s", process, mach_error_string(result));
			} else if (!MACH_PORT_VALID(task)) {
				if (task != MACH_PORT_NULL)
					mach_port_deallocate(mach_task_self(), task);
				task = MACH_PORT_NULL;
				NSLog(@"Mach port is not valid for process %d", process);
			} else {
				NSLog(@"Successfully acquired task for process %d",process); // task for the process has been acquired, now setup the search parameters
				struct SearchData *searchData = malloc(sizeof(struct SearchData));
				mach_vm_size_t length = 0;
				searchData->searchValue = valueFromString(@"|HOnlUser:", &length); // look for instances of a user's tag name, this can be found by grabbing them from chat channels
				searchData->dataSize = length;
				searchData->dataAlignment = sizeof(int8_t);
				searchData->beginAddress = 0x0;
				searchData->endAddress = ((mach_vm_address_t)MACH_VM_MAX_ADDRESS);
				search_for_data_t searchForDataCallback = ^(struct SearchData *searchData, void *variableData, void *compareData, mach_vm_address_t address) { // building the callback for when tag names are found
					struct TagName returnTag = (struct TagName){0x0, 0, task};
					if ((strncmp(variableData, compareData, (size_t)searchData->dataSize) == 0)) { // check if the given string is equal
						mach_vm_address_t tagNameAddress = address + searchData->dataSize; // shift address to end of the string in memory
						char *findName = "|h[";
						tagNameAddress += LengthUntilString(task, tagNameAddress, findName, strlen(findName)) + strlen(findName); // finding the length of the chat ID for a user, and adding that to address
						char *closingBracket = "]";
						mach_vm_size_t tagLength = LengthUntilString(task, tagNameAddress, closingBracket, strlen(closingBracket)); // finding the length of the tag name
						char *bytes = NULL;
						if (ReadBytes(task, tagNameAddress, (void **)&bytes, &tagLength)) { // reading the tag name
							if (bytes && strlen(bytes)) // verifying the tag name is not and empty string
								returnTag = (struct TagName){tagNameAddress, tagLength, task}; // returning TagName struct which stores where the tag name is in memory and how long it is
						}
						mach_vm_deallocate(current_task(), (vm_offset_t)bytes, tagLength); // freeing the bytes just read for the tag name
					}
					return returnTag; // returning nothing, this isn't an instance of a tag name
				}; // end of callback
				SearchForData(task, searchData, potentialbattleTags, battleTags, searchForDataCallback); // executing master search through memory to find instances of potential tag names
				NSLog(@"%zi BattleTags found.", battleTags.count); // what is the total number of tags found?
				free(searchData); // search is finished, free up memory used for search parameters
				mach_port_deallocate(mach_task_self(), task);
			}
		}
	}
	[pool drain]; // drain the pool, nothing else to do
	return 0;
}