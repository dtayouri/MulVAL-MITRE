import pandas
import numpy
import tkinter
from tkinter import *
from tkinter import ttk
import webbrowser
import textwrap
import checklistcombobox as clc

FIRST_COLUMN_WIDTH = 500
SECOND_COLUMN_WIDTH = 550

# Wraps the given string by every length characters
def wrap(string, lenght=40):
    return '\n'.join(textwrap.wrap(string, lenght))

# Main GUI method
def displayTTP(irsDF):
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
        createPddlFile(irTreeView)

    # When hovering over a row show the IR in a tooltip window
    def showTooltip(event):
        tree = event.widget
        item = tree.identify_row(event.y)
        tipText = ''
        if item != '':
            if event.x < FIRST_COLUMN_WIDTH:
                tipText = tree.item(item, "values")[0]
            elif event.x > FIRST_COLUMN_WIDTH and event.x < FIRST_COLUMN_WIDTH+SECOND_COLUMN_WIDTH:
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
    fontTuple = ("Times new roman", 11, "normal")

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
    irTreeView = ttk.Treeview(mainframe, column=(1, 2, 3), show='headings')
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
    style.configure('Treeview', rowheight=70)  # Add the rowheight

    root.mainloop()

# Build list of interaction rules from the given dataframe
# Also build of techniques for filtering
def buildIrList(irsDF, irTreeView):
    techniqueList = []
    for irItem in irTreeView.get_children():
        irTreeView.delete(irItem)
    for i in irsDF.index:
        ir = irsDF["Interaction Rules"][i]
        if pandas.isna(ir) or ir == '':
            ir = irsDF["Predicate"][i]
        if pandas.isna(ir) or ir.strip() == '':  # If there is no IR or fact, ignore
            continue
        wrappedDesc = wrap(irsDF["Explanation"][i], 100)
        mappedTechnique = irsDF["MITRE Enterprise Technique"][i]
        for technique in mappedTechnique.split('\n'):
            if technique.strip() != '' and not technique in techniqueList:
                techniqueList.append(technique)
        lineTag = 'line'+str(len(irTreeView.get_children()) % 2)
        irTreeView.insert('', 'end', text="1", values=(ir, wrappedDesc, mappedTechnique), tag=lineTag)
    irTreeView.tag_configure('line0', background='gray')  # This highlights each second line, but the highlight is not visible in every monitor
    return techniqueList


# Save the filtered rows of IR TreeView as PDDL file
# Todo: Smart Recursive Save: The user may request to export a selected (filtered) set of IRs.
# In this case, all the predicates in the body of the IR should be checked – if they are IRs themselves,
# all the instances should also be saved
def createPddlFile(irTreeView):
    fileStream = open("IRs.p", "w")
    fileStream.write('/*************************/\n'
                     '/ Predicates Declarations /\n'
                     '/*************************/\n')
    # Sample output:
    # primitive(dependsOn(_software, _component)).
    # derived(vulnerableSoftware(_software)).
    primitives = []
    deriveds = []
    for row in irTreeView.get_children():
        ir = irTreeView.item(row, "values")[0]
        mappedTechnique = irTreeView.item(row, "values")[2]
        generalizedIr, irName = generalize(ir)
        if mappedTechnique == 'Fact':  # This is a primitive
            if irName in primitives:
                continue
            primitives.append(irName)
            line = "primitive({}).\n".format(generalizedIr)
        else:  # This is a derived
            if irName in deriveds:
                continue
            deriveds.append(irName)
            line = "derived({}).\n".format(generalizedIr)
        fileStream.write(line)

    line = "\nmeta(attackGoal(_)).\n\n"
    fileStream.write(line)

    fileStream.write('/*******************************************/\n'
                     '/****      Tabling Predicates          *****/\n'
                     '/* All derived predicates should be tabled */''\n'
                     '/*******************************************/\n')
    # Sample output:
    # :- table vulnerableSoftware/1.
    for derived in deriveds:
        line = ":- table {}.\n".format(derived)
        fileStream.write(line)

    fileStream.write('\n/*******************/\n'
                     '/ Interaction Rules /\n'
                     '/*******************/\n')
    # Sample output:
    # interaction_rule(
    #   (vulnerableComponent(Component) :-
    #     vulExists(_cvId, Component, _range_types, _lose_types, _severity, _access)),
    #   rule_desc('vulnerability in a component', 1.0)).
    for row in irTreeView.get_children():
        ir = irTreeView.item(row, "values")[0]
        description = irTreeView.item(row, "values")[1].replace('\n', ' ')  # Remove new lines
        mappedTechnique = irTreeView.item(row, "values")[2]
        if mappedTechnique == 'Fact':  # This is a primitive
            continue
        lastDot = ir.rfind('.')
        if lastDot != -1:
            ir = ir[0:lastDot]
        line = "interaction_rule(\n ({}),\n rule_desc('{}', 1.0)).\n\n".format(ir, description)
        fileStream.write(line)

    fileStream.close()

# Generalize given IR parameters by adding '_' at the bgeining of each parameter
def generalize(ir):
    # Remove body and last dot (if any)
    divider = ir.find(':-')
    if divider == -1:  # Primitive
        divider = ir.find('.')
        if divider == -1:
            irHead = ir
        else:
            irHead = ir[0:divider]
    else:
        irHead = ir[0:divider]

    # Add '_' to each parameter (if not already exists)
    paramCount = 0
    irHead = irHead.strip()
    divider = irHead.find('(')
    irName = irHead[0:divider]
    generalizedIr = irName + '('
    nextDivider = irHead.find(',')
    while nextDivider != -1:
        param = irHead[divider+1:nextDivider].strip()
        if not param.startswith('_'):
            param = '_' + param
        generalizedIr += param + ', '
        paramCount += 1
        divider = nextDivider
        nextDivider = irHead.find(',', divider+1)
    nextDivider = irHead.find('),', divider+1)
    param = irHead[divider+1:nextDivider].strip()
    if not param.startswith('_'):
        param = '_' + param
    generalizedIr += param + ')'
    paramCount += 1

    # Add to irName the number of parameters
    irName = "{}/{}".format(irName, paramCount)

    return generalizedIr, irName

if __name__ == '__main__':
    # Read relationships, which include Data Components, from CSV to DataFrame
    irsFilePath = "file:MulVAL to MITRE-for IRMA.xlsx"  # Read from local path
    irsDF = pandas.read_excel(irsFilePath, keep_default_na=False)
    displayTTP(irsDF)
