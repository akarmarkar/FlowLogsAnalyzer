#!/usr/bin/python3

from dataclasses import dataclass
import logging
import sys
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

# Invoke the program as python3 main.py <PATH_TO_FLOW_LOGS.csv> <PATH_TO_TAG_MAPPINGS.csv> <PATH_TO_OUTPUT.csv>
# TODO:
# - Add flags parsing instead of accepting commandline args
# - Stronger type checking
# - Custom formats
# - Add more complete enums (see definitions below)

class IANAProtocolNum(Enum):
    ICMP = "1"
    IPv4 = "4"
    TCP = "6"
    UDP = "17"
    IPv6 = "41"

COUNT = 1
class Action(Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    UNKNOWN = "-"
class LogStatus(Enum):
    ACCEPT = "OK"
    REJECT = "NODATA"
    UNKNOWN = "SKIPDATA"
@dataclass
class FlowLogRecordV2(object):
    version: int
    accountId: str
    interfaceId: str
    srcAddr: str
    dstAddr: str
    srcPort: int
    dstPort: int
    protocol: IANAProtocolNum
    packets: int
    numBytes: int
    startTimeSecs: int
    endTimeSecs: int
    action: Action # enum: ACCEPT,REJECT
    logStatus: LogStatus # enum : OK,NODATA,SKIPDATA

@dataclass
class TagRecord(object):
    dstPort: int
    protocol: str
    tag: str

def genFields(path: str,lineLambda,splitChar:str=",") -> str:
    """
    Accepts a tag file path and parses it, skipping invalid records.
    :return: Yields a string
    """
    with open(path, "r") as f:
        # Skip the first line as it contains the csv header information
        logger.info(f"CSV Header:{f.readline().strip()}")
        for line in f:
            line = lineLambda(line)
            parts = line.split(splitChar)
            yield parts

def genRecord(path:str,recordCls,lineLambda=lambda line:line.strip())->TagRecord:
    """
    Accepts a tag file path and parses it, skipping invalid records.
    :return: Yields a valid tag record
    """
    counter,skipped = 0,0
    _types = recordCls.__annotations__.values()

    for parts in genFields(path,lineLambda):
        if len(parts) != len(_types):
            logger.info(f"Skipping invalid record: {','.join(parts)}")
            continue
        try:
            r = recordCls(*[_typ(v) for _typ, v in zip(_types, parts)])
            yield r
            counter += 1
        except Exception as e:
            logger.warning(f"Skipping line:{','.join(parts)}, Error:{e}")
            skipped += 1
    logger.info(f"Completed parsing all {recordCls.__name__} records. OK:{counter},skipped:{skipped},total:{skipped+counter}")

def main(flowlogsPath:str,tagMappingsPath:str,outputPath:str):
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    tagMappings = { }
    untaggedCounter = 0
    # Make matching case insensitive by converting to lowercase
    for tagRecord in genRecord(tagMappingsPath,TagRecord,lineLambda=lambda line:line.strip().lower()):
        #logger.info(f"TAG={tagRecord.tag}")
        tagMappings[(tagRecord.dstPort,tagRecord.protocol)] = [tagRecord,0]

    for flowRecord in genRecord(flowlogsPath, FlowLogRecordV2):
        # Make matching case insensitive by converting to lowercase
        protocolStr = str(flowRecord.protocol).lower().replace("ianaprotocolnum.","")
        logger.info(f"{flowRecord.dstPort},{str(flowRecord.protocol.value)}")
        if (flowRecord.dstPort,protocolStr) in tagMappings:
            tagMappings[(flowRecord.dstPort,protocolStr)][COUNT] += 1
        else:
            untaggedCounter += 1

    with open(outputPath,"w") as f:
        tagCounts = defaultdict(int)
        for dstPort, protocolStr in tagMappings.keys():
            tagRecord = tagMappings[(dstPort, protocolStr)][0]
            tagCounts[tagRecord.tag] += tagMappings[(dstPort, protocolStr)][COUNT]

        f.write("Tag,Count\n")
        for tag,count in tagCounts.items():
            f.write(f"{tag},{count}\n")

        f.write("Port,Protocol,Count\n")
        for dstPort,protocolStr in tagMappings.keys():
            f.write(f"{dstPort},{protocolStr},{tagMappings[(dstPort,protocolStr)][COUNT]}\n")

        f.write(f"Untagged,{untaggedCounter}\n")
def usage():
    print("python3 main.py <PATH_TO_FLOW_LOGS.csv> <PATH_TO_TAG_MAPPINGS.csv> <PATH_TO_OUTPUT.csv>")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        usage()
        exit(1)
    main(sys.argv[1],sys.argv[2],sys.argv[3])