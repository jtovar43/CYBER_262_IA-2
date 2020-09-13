# Justin Tovar
# jqt5481@psu.edu
# IA-2 CYBER 262

from prettytable import PrettyTable

# Prep input and output files
output_file = open('Output.txt', 'w')

file_path = 'Log-A.strace'
workingFile = open(file_path, 'r')
logContentA = workingFile.readlines()
workingFile.close()

file_path = 'Log-B.strace'
workingFile = open(file_path, 'r')
logContentB = workingFile.readlines()
workingFile.close()

######################## BEGIN OUTPUT A #############################
tableA = PrettyTable()

def getReadEvents(content):
    fileCount = 0
    keyCount = 0
    pipeCount = 0
    for line in content:
        if "read" in line and "tty" not in line and "pipe" not in line:
            fileCount += 1
        if "read" in line and 'tty' in line:
            keyCount += 1
        if "read" in line and 'pipe' in line:
            pipeCount += 1
    readEvents = [fileCount, keyCount, pipeCount]
    return readEvents

tableA.title = "Output A Results"
tableA.field_names = ["Event Type", "A", "B"]
tableA.add_row(['File Read Events', getReadEvents(logContentA)[0], getReadEvents(logContentB)[0]])
tableA.add_row(['Keyboard Read Events', getReadEvents(logContentA)[1], getReadEvents(logContentB)[1]])
tableA.add_row(['Read from Pipe Events', getReadEvents(logContentA)[2], getReadEvents(logContentB)[2]])

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

for event in getNameandTimestamp(logContentA):
    if event in getNameandTimestamp(logContentB):
        tableC.add_row([event, getNameandTimestamp(logContentA)[event], getNameandTimestamp(logContentB)[event]])
    else:
        tableC.add_row([event, getNameandTimestamp(logContentA)[event], "absent"])

print(tableC, file=output_file)

######################## BEGIN OUTPUT D #############################
tableD = PrettyTable()
tableD.title = "Output D Results"

def getUserEvents(content):
    keystrokes = []
    for line in content:
        if ' read(' in line and 'tty' in line:
            start = line.find('"')
            end = line.find('"', start+1)
            keystroke = line[start+1 : end]
            keystrokes.append(keystroke)
    return keystrokes

print(tableD, file='output.txt')
print("Log A Keystrokes", getUserEvents(logContentA))
print("The user provides the following keystrokes to the console:")


# Close output file
output_file.close()
