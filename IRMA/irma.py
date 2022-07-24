import pandas
import tkinter
from tkinter import *
from tkinter import ttk
import textwrap
import checklistcombobox as clc
import queue

FIRST_COLUMN_WIDTH = 500
SECOND_COLUMN_WIDTH = 550

# Wrap the given string by every length characters
def wrap(string, length=40):
    return '\n'.join(textwrap.wrap(string, length))

# Main GUI method
def displayIrs(irsDF):
    # Filter the list by filter options
    def filterList():
        # If filter by IR head or body is required
        irHeadFilter = irHeadFilterEntry.get()
        irBodyFilter = irBodyFilterEntry.get()
        if irHeadFilter != '' or irBodyFilter != '':
            for irItem in irTreeView.get_children():
                # Divide IR into head and body and search in each
                ir = irTreeView.item(irItem)['values'][0]
                divider = ir.find(':-')
                if divider == -1:
                    irHead = ir
                    irBody = ''
                else:
                    irHead = ir[0:divider]
                    irBody = ir[divider+2:]
                if (irHeadFilter != '' and irHeadFilter in irHead) or (irBodyFilter != '' and irBodyFilter in irBody):
                    continue
                irTreeView.detach(irItem)  # Remove the row

        # If filter by IR description is required
        irDescFilter = irDescFilterEntry.get()
        if irDescFilter != '':
            for irItem in irTreeView.get_children():
                irDesc = irTreeView.item(irItem)['values'][1]
                if irDescFilter != '' and irDescFilter in irDesc:
                    continue
                irTreeView.detach(irItem)

        # If filter by IR description is required
        # get() returns str if a single value is selected, otherwise it returns list of strings
        techniqueFilters = techniqueFilterCombo.get()
        if techniqueFilters == '':
            return
        if isinstance(techniqueFilters, str):
            techniqueFilters = [techniqueFilters]
        for irItem in irTreeView.get_children():
            technique = irTreeView.item(irItem)['values'][2]
            # techniqueFilters may include several techniques; search each in the technique cell
            ifRemove = True
            for techniqueFilter in techniqueFilters:
                if techniqueFilter in technique:
                    ifRemove = False
                    break
            if ifRemove:
                irTreeView.detach(irItem)

    # Clear filters and restore to list to the initial state
    def clearFilter():
        irHeadFilterEntry.delete(0, END)
        irBodyFilterEntry.delete(0, END)
        irDescFilterEntry.delete(0, END)
        # Clear technique filter combo-box
        for button in techniqueFilterCombo.checkbuttons:
            button.deselect()
        techniqueFilterCombo.set('')
        techniqueList = buildIrList(irsDF, irTreeView)

    def createPddl():
        createPddlFile(irsDF, irTreeView)

    # When hovering over a row show the IR in a tooltip window
    def showTooltip(event):
        tree = event.widget
        item = tree.identify_row(event.y)
        tipText = ''
        if item != '':
            if event.x < FIRST_COLUMN_WIDTH:
                tipText = tree.item(item, "values")[0]
            elif FIRST_COLUMN_WIDTH < event.x < FIRST_COLUMN_WIDTH+SECOND_COLUMN_WIDTH:
                tipText = tree.item(item, "values")[1]
            else:
                tipText = tree.item(item, "values")[2]
        if tipText != '':
            toolTip.config(text=tipText)
            toolTip.place(x=event.x, y=event.y)
        else:
            toolTip.place_forget()

    root = tkinter.Tk()
    root.title("IRMA - A Tool For managing existing Interaction Rules")
    root.geometry("1400x900")

    # Add a grid
    mainframe = Frame(root)
    mainframe.grid(column=0, row=0, columnspan=10, rowspan=13, sticky=(N, W, E, S))
    mainframe.columnconfigure(0, weight=1)
    mainframe.rowconfigure(0, weight=1)
    mainframe.pack(pady=20, padx=20)

    Label(mainframe, text="Filter by", height=2).grid(row=1, column=1)
    Label(mainframe, text="Rule Head:", width=20, height=2).grid(row=2, column=1)
    irHeadFilterEntry = Entry(mainframe, width=30)
    irHeadFilterEntry.grid(row=2, column=2, columnspan=2, rowspan=1)
    Label(mainframe, text="Rule Body:", height=2).grid(row=3, column=1)
    irBodyFilterEntry = Entry(mainframe, width=30)
    irBodyFilterEntry.grid(row=3, column=2, columnspan=2, rowspan=1)
    Label(mainframe, text="Description keywords:", height=2).grid(row=2, column=4)
    irDescFilterEntry = Entry(mainframe, width=40)
    irDescFilterEntry.grid(row=2, column=5, columnspan=2, rowspan=1)
    Label(mainframe, text="Technique:", height=2).grid(row=2, column=7)
    filterButton = Button(mainframe, text='Filter', width=15, command=filterList)
    filterButton.grid(row=4, column=5, columnspan=1, rowspan=1)
    clearButton = Button(mainframe, text='Clear Filter', width=15, command=clearFilter)
    clearButton.grid(row=4, column=6, columnspan=1, rowspan=1)
    createPddlButton = Button(mainframe, text='Create PDDL File', width=15, command=createPddl)
    createPddlButton.grid(row=4, column=9, columnspan=1, rowspan=1)

    Label(mainframe, text="", height=1).grid(row=5, column=1)
    irTreeView = ttk.Treeview(mainframe, columns=(1, 2, 3), show='headings')
    irTreeView.column(1, anchor=W, width=FIRST_COLUMN_WIDTH)
    irTreeView.column(2, anchor=W, width=SECOND_COLUMN_WIDTH)
    irTreeView.column(3, anchor=CENTER, width=270)
    irTreeView.heading(1, text='Interaction Rule', anchor=CENTER)
    irTreeView.heading(2, text='Description', anchor=CENTER)
    irTreeView.heading(3, text='Mapped Technique', anchor=CENTER)
    irTreeView.bind("<Motion>", showTooltip)
    techniqueList = buildIrList(irsDF, irTreeView)
    irScroll = Scrollbar(mainframe)
    irTreeView.configure(yscrollcommand=irScroll.set)
    irTreeView.grid(row=6, column=1, columnspan=9, rowspan=8)
    irScroll.config(command=irTreeView.yview)
    irScroll.grid(row=6, column=10, columnspan=1, rowspan=8, sticky='ENS')
    toolTip = Label(irTreeView, bg="yellow", justify=LEFT, relief=SOLID, borderwidth=1)

    # Build a multi-select combo box for techniques
    techniqueFilterCombo = clc.ChecklistCombobox(
        mainframe, state='readonly', checkbutton_height=1, width=50, height=20, values=techniqueList)
    techniqueFilterCombo.grid(row=2, column=8, columnspan=2, rowspan=1)

    style = ttk.Style()
    style.theme_use("clam")
    style.map("Treeview")
    style.configure('Treeview', rowheight=70)  # Add the row height

    root.mainloop()

# Build list of interaction rules from the given dataframe
# Also build of techniques for filtering
def buildIrList(irsDF, irTreeView):
    techniqueList = []
    for irItem in irTreeView.get_children():
        irTreeView.delete(irItem)
    for i in irsDF.index:
        primitiveOrDerived = irsDF["Primitive/Derived"][i]
        if "Complex" in primitiveOrDerived or "Mixed" in primitiveOrDerived:
            continue
        ir = irsDF["Interaction Rules"][i]
        if pandas.isna(ir) or ir == '':
            ir = irsDF["Predicate"][i]
        if pandas.isna(ir) or ir.strip() == '':  # If there is no IR or fact, ignore
            continue
        wrappedDesc = wrap(irsDF["Explanation"][i], 100)
        mappedTechnique = irsDF["MITRE Enterprise Technique"][i]
        for technique in mappedTechnique.split('\n'):
            if technique.strip() != '' and technique not in techniqueList:
                techniqueList.append(technique)
        lineTag = 'line'+str(len(irTreeView.get_children()) % 2)
        irTreeView.insert('', 'end', text="1", values=(ir, wrappedDesc, mappedTechnique), tag=lineTag)
    irTreeView.tag_configure('line0', background='lightgray')  # This highlights each second line (not always visible)
    return techniqueList

# Save the filtered rows of IR TreeView as PDDL file.
# Smart Recursive Save: The user may request to export a selected (filtered) set of IRs.
# In this case, all the predicates in the body of the IR should be checked – if they are IRs themselves,
# they should also be saved
def createPddlFile(irsDF, irTreeView):
    # Before saving, for each IR bring the IRs it uses
    # Each primitive/derived is a set of (irSignature, ir, generalizedIr, description)
    primitives, deriveds, uniqueDeriveds = findAllRequiredIrs(irsDF, irTreeView)

    fileStream = open("IRs.p", "w")
    fileStream.write('/*************************/\n'
                     '/ Predicates Declarations /\n'
                     '/*************************/\n')
    # Sample output:
    # primitive(dependsOn(_software, _component)).
    # derived(vulnerableSoftware(_software)).
    for primitive in primitives:
        generalizedPredicate = primitive[2]
        line = "primitive({}).\n".format(generalizedPredicate)
        fileStream.write(line)

    for derived in uniqueDeriveds:
        generalizedPredicate = derived[2]
        line = "derived({}).\n".format(generalizedPredicate)
        fileStream.write(line)

    line = "\nmeta(attackGoal(_)).\n\n"
    fileStream.write(line)

    fileStream.write('/*******************************************/\n'
                     '/****      Tabling Predicates          *****/\n'
                     '/* All derived predicates should be tabled */''\n'
                     '/*******************************************/\n')
    # Sample output:
    # :- table vulnerableSoftware/1.
    for derived in uniqueDeriveds:
        irSignature = derived[0]
        line = ":- table {}.\n".format(irSignature)
        fileStream.write(line)

    fileStream.write('\n/*******************/\n'
                     '/ Interaction Rules /\n'
                     '/*******************/\n')
    # Sample output:
    # interaction_rule(
    #   (vulnerableComponent(Component) :-
    #     vulExists(_cvId, Component, _range_types, _lose_types, _severity, _access)),
    #   rule_desc('vulnerability in a component', 1.0)).
    for derived in deriveds:
        ir = derived[1]
        description = derived[3]
        lastDot = ir.rfind('.')
        if lastDot != -1:
            ir = ir[0:lastDot]
        line = "interaction_rule(\n ({}),\n rule_desc('{}', 1.0)).\n\n".format(ir, description)
        fileStream.write(line)

    fileStream.close()

# Return the list of selected IRs (divided to primitives and deriveds) and the IRs used by them.
# First handle the selected IRs (put them in the lists), and put the derived ones in a queue.
# For each IR in the queue, bring its body/bodies (the same IR signature may have several implementations);
# After handling the body's IRs, put the derived ones in a queue, and so on recursively.
def findAllRequiredIrs(irsDF, irTreeView):
    primitives = []
    deriveds = []
    uniqueDeriveds = []
    irsToHandleQueue = queue.Queue()
    for row in irTreeView.get_children():
        ir = irTreeView.item(row, "values")[0]
        _, irSignature, _ = generalizeIrParams(ir)
        irsToHandleQueue.put(irSignature)

    # Search the irSignature in the irsDF, and for each instance, add it to list and add the body predicates to queue
    missingIrs = []
    while not irsToHandleQueue.empty():
        irToHandle = irsToHandleQueue.get()
        irFound = False
        for i in irsDF.index:
            primitiveOrDerived = irsDF["Primitive/Derived"][i]
            if "Complex" in primitiveOrDerived or "Mixed" in primitiveOrDerived:
                continue
            ir = irsDF["Interaction Rules"][i]
            if pandas.isna(ir) or ir == '':
                ir = irsDF["Predicate"][i]
            if pandas.isna(ir) or ir.strip() == '':  # If there is no IR or fact, ignore
                continue
            description = irsDF["Explanation"][i]
            generalizedIr, irSignature, isDerived = generalizeIrParams(ir)
            if irSignature != irToHandle:
                continue
            irFound = True
            if not isDerived:  # This is a primitive
                if not isInList(irSignature, primitives):
                    primitives.append((irSignature, ir, generalizedIr, description))
                continue
            # This is a derived
            if not isInList(irSignature, uniqueDeriveds):
                uniqueDeriveds.append((irSignature, ir, generalizedIr, description))
            # deriveds may include several instances of the same IR signature
            # Todo: hanlde cases that ir cell includes a Mixed set of IRs (SIR)
            deriveds.append((irSignature, ir, generalizedIr, description))
            bodyIrs = getBodyIrs(ir)
            for bodyIr in bodyIrs:
                _, irSignature, _ = generalizeIrParams(bodyIr)
                if not isInList(irSignature, uniqueDeriveds):
                    irsToHandleQueue.put(irSignature)

        if not irFound:
            if irToHandle not in missingIrs:
                missingIrs.append(irToHandle)

    for missingIr in missingIrs:
        print("The IR '{}' was not found in the whole list of IRs".format(missingIr))

    return primitives, deriveds, uniqueDeriveds

# Generalize given IR head's parameters by adding '_' at the bgeining of each parameter
def generalizeIrParams(ir):
    # Remove body and last dot (if any)
    isDerived = False
    divider = ir.find(':-')
    if divider == -1:  # Primitive
        divider = ir.find('.')
        if divider == -1:
            irHead = ir
        else:
            irHead = ir[0:divider]
    else:
        irHead = ir[0:divider]
        isDerived = True

    generalizedIr, irSignature = generalizePredicateAndGetSignature(irHead.strip())
    return generalizedIr, irSignature, isDerived

# Generalize given predicate parameters by adding '_' at the beginning of each parameter
# Return also the predicate signature in the form of predicateName/numberOfParams
def generalizePredicateAndGetSignature(predicate):
    # Add '_' to each parameter (if not already exists)
    paramCount = 0
    divider = predicate.find('(')
    predicateName = predicate[0:divider]
    generalizedPredicate = predicateName + '('
    nextDivider = predicate.find(',')
    while nextDivider != -1:
        param = predicate[divider+1:nextDivider].strip()
        if not param.startswith('_'):
            param = '_' + param
        generalizedPredicate += param + ', '
        paramCount += 1
        divider = nextDivider
        nextDivider = predicate.find(',', divider+1)
    nextDivider = predicate.find('),', divider+1)
    param = predicate[divider+1:nextDivider].strip()
    if not param.startswith('_'):
        param = '_' + param
    generalizedPredicate += param + ')'
    paramCount += 1

    # Add to predicateName the number of parameters
    predicateSignature = "{}/{}".format(predicateName, paramCount)

    return generalizedPredicate, predicateSignature

# Check if the IR signature is in the list that includes sets of (irSignature, ir, generalizedIr, description)
def isInList(irSignature, irList):
    for irSet in irList:
        if irSignature == irSet[0]:
            return True
    return False

# Return IR's body as list of predicates
def getBodyIrs(ir):
    bodyPredicates = []
    divider = ir.find(':-')
    if divider != -1:
        body = ir[divider+2:].strip()
        divider = 0
        nextDivider = body.find(')')
        while nextDivider != -1:
            predicate = body[divider:nextDivider+1].strip()
            if predicate not in bodyPredicates:
                bodyPredicates.append(predicate)
            divider = nextDivider + 2  # 2 is for '),'
            nextDivider = body.find(')', divider)

    return bodyPredicates


if __name__ == '__main__':
    # Read relationships, which include Data Components, from CSV to DataFrame
    irsFilePath = "file:MulVAL to MITRE-for IRMA.xlsx"  # Read from local path
    irsDF = pandas.read_excel(irsFilePath, keep_default_na=False)
    displayIrs(irsDF)
