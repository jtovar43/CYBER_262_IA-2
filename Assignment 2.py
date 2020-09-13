# Justin Tovar
# jqt5481@psu.edu
# IA-2 CYBER 262

from prettytable import PrettyTable

######################## BEGIN OUTPUT A #############################
output_file = open('Output.txt', 'w')

file_path = 'Log-A.strace'
workingFile = open(file_path, 'r')
logContentA = workingFile.readlines()
workingFile.close()

file_path = 'Log-B.strace'
workingFile = open(file_path, 'r')
logContentB = workingFile.readlines()
workingFile.close()

tableA = PrettyTable()
fileReadEventsA = 0
keyReadEventsA = 0
pipeReadEventsA = 0
fileReadEventsB = 0
keyReadEventsB = 0
pipeReadEventsB = 0

for line in logContentA:
    if "read" in line and "tty" not in line and "pipe" not in line:
        fileReadEventsA += 1
    if "read" in line and 'tty' in line:
        keyReadEventsA += 1
    if "read" in line and 'pipe' in line:
        pipeReadEventsA += 1
    
for line in logContentB:
    if "read" in line and "tty" not in line and "pipe" not in line:
        fileReadEventsB += 1
    if "read" in line and 'tty' in line:
        keyReadEventsB += 1
    if "read" in line and 'pipe' in line:
        pipeReadEventsB += 1

tableA.title = "Output A Results"
tableA.field_names = ["Event Type", "A", "B"]
tableA.add_row(['File Read Events', fileReadEventsA, fileReadEventsB])
tableA.add_row(['Keyboard Read Events', keyReadEventsA, keyReadEventsB])
tableA.add_row(["Read from Pipe Events", pipeReadEventsA, pipeReadEventsB])

print(tableA, file=output_file)

######################## BEGIN OUTPUT B #############################
tableB = PrettyTable()
tableB.title = "Output B Results"
tableB.field_names = ["Event Type","A", "B"]

def countEvents(content, keyword):
    count = 0
    for line in content:
        if keyword in line:
            count +=1
    return count

tableB.add_row(["Program Start Events", countEvents(logContentA,'execve'), countEvents(logContentB,'execve')])
tableB.add_row(["Write Events", countEvents(logContentA,'write'), countEvents(logContentB,'write')])
tableB.add_row(["Get File/Directory Status Events", countEvents(logContentA,'access') + countEvents(logContentA,'stat'), countEvents(logContentB,'access') + countEvents(logContentB,'stat')])
tableB.add_row(["File Unlinking Event", countEvents(logContentA,'unlinkat'), countEvents(logContentB,'unlinkat')])
tableB.add_row(["Program End Events", countEvents(logContentA,'exit_group'), countEvents(logContentB,'exit_group')])

print(tableB, file=output_file)

######################## BEGIN OUTPUT C #############################
tableC = PrettyTable()
tableC.title = "Output C Results"
tableC.field_names = ["Name of Executable", "Log A Timestamp", "Log B Timestamp"]

def storeEvents(content, keyword):
    eventList = list()
    for line in content:
        if keyword in line:
            eventList.append(line)
    return eventList

def getNameandTimestamp(content):
    execNamesAndTime = {}
    for line in content:
        if ' execve(' in line:
            startPos = line.find('"')
            endPos = line.find('"', startPos + 1)
            name = line[startPos + 1:endPos]
            if name not in execNamesAndTime:
                execNamesAndTime[name] = line[0:5]
    return execNamesAndTime

print(getNameandTimestamp(logContentA))
print(getNameandTimestamp(logContentB))


print(tableC, file=output_file)

# Close output file
output_file.close()