import mitreattack.attackToExcel.stixToDf as stixToDf
from stix2 import MemoryStore, Filter
import requests
import pandas
import tkinter
from tkinter import *
from tkinter import ttk
import webbrowser
import textwrap

TACTIC_HIGHLIGHT = '#98FB98'
TECHNIQUE_HIGHLIGHT = '#54FF9F'
SUBTECHNIQUE_HIGHLIGHT = '#00CD66'

# Opens given URL in a browser's tab
def openURL(url):
    webbrowser.open_new(url)

# Wraps the given string by every length characters
def wrap(string, lenght=40):
    return '\n'.join(textwrap.wrap(string, lenght))

# Helper method for testing data of ATT&CK STIX (brought from json)
def printTacticTecniqueFromStix(attackStix):
    # Get Tactics
    filter = [
        Filter('type', '=', 'x-mitre-tactic'),
    ]
    tactics = attackStix.query(filter)
    for tactic in tactics:
        print(tactic['x_mitre_shortname'])
        print(tactic['external_references'][0]['external_id'] + ' ' + tactic['name'])
        print(tactic['description'])

    tactics = buildTacticList(attackStix)
    tacticId = tactics[0].split(' ')[0]  # Extract the ID that is the first part of the string
    tacticDescription = getTacticField(attackStix, tacticId, 'description')

    # Techniques map into tactics by use of their kill_chain_phases property.
    # Where the kill_chain_name is mitre-attack (for enterprise), the phase_name corresponds to the x_mitre_shortname property of an x-mitre-tactic object.
    # Get Techniques of 'Collection' Tactic (TA0009)
    filter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
        Filter('kill_chain_phases.phase_name', '=', 'collection')
    ]
    techniques = attackStix.query(filter)
    for technique in techniques:
        print(technique['external_references'][0]['external_id'] + ' ' + technique['name'])
        print(technique['description'])

    techniques = buildTechniqueList(attackStix, tacticId)
    techniqueID = techniques[0].split(' ')[0]  # Extract the ID that is the first part of the string
    techniqueDescription, techniquePlatforms = getTechniqueDetails(attackStix, techniqueID)
    print(techniqueDescription, techniquePlatforms)
    subtechniques = buildSubtechniqueList(attackStix, techniqueID)
    subtechniqueID = subtechniques[0].split(' ')[0]  # Extract the ID that is the first part of the string
    subtechniqueDescription, subtechniquePlatforms = getTechniqueDetails(attackStix, subtechniqueID)
    print(subtechniqueDescription, subtechniquePlatforms)

# Main GUI method
def displayTTP(attackStix, relationshipsDF, predicatesQuestionsAndDataComponentsDF, entitiesDF):
    # Methods for selection events
    def tacticSelected(self, *args):
        deleteText(tacticDescriptionText)
        if tacticVar.get() == '':
            return
        # Display Tactic description
        tacticID = tacticVar.get().split(' ')[0] # Extract the ID that is the first part of the string
        tacticDescription = getTacticField(attackStix, tacticID, 'description')
        insertText(tacticDescriptionText, tacticDescription)
        # Update Technique drop-down
        techniques = buildTechniqueList(attackStix, tacticID)
        techniqueCombo.config(value=techniques)
        techniqueCombo.set('')
        subtechniqueCombo.set('')
        global entitiesInTactic  # Entities found in the description of selected Tactic
        entitiesInTactic, foundEntitiesAndSynonyms = findEntitiesInText(tacticDescription, entitiesDF)
        # Highlight in the description entities and their synonyms
        highlight(tacticDescriptionText, foundEntitiesAndSynonyms, TACTIC_HIGHLIGHT)

    def techniqueSelected(self, *args):
        deleteText(techniqueDescriptionText)
        deleteText(techniquePlatformsText)
        deleteText(techniqueCapecIdText)
        dataComponentsListBox.delete(0, dataComponentsListBox.size())
        for item in dcInterctionRuleTreeView.get_children():
            dcInterctionRuleTreeView.delete(item)
        entitiesListBox.delete(0, entitiesListBox.size())
        questionsListBox.delete(0, questionsListBox.size())
        questionsIrListBox.delete(0, questionsIrListBox.size())
        if techniqueVar.get() == '':
            return
        # Display Technique description
        techniqueID = techniqueVar.get().split(' ')[0] # Extract the ID that is the first part of the string
        techniqueDescription, techniquePlatforms = getTechniqueDetails(attackStix, techniqueID)
        insertText(techniqueDescriptionText, techniqueDescription)

        # Update Subtechnique drop-down
        subtechniques = buildSubtechniqueList(attackStix, techniqueID)
        subtechniqueCombo.config(value=subtechniques)
        subtechniqueCombo.set('')

        # Update platforms and CAPEC-ID
        platforms = ''
        for platform in techniquePlatforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, techniqueID)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(techniqueID, relationshipsDF, dataComponentsListBox)
        global entitiesInTechnique # Entities found in the description of selected Technique
        entitiesInTechnique, foundEntitiesAndSynonyms = findEntitiesInText(techniqueDescription, entitiesDF)
        # Highlight in the description entities and their synonyms
        highlight(techniqueDescriptionText, foundEntitiesAndSynonyms, TECHNIQUE_HIGHLIGHT)
        updateEntities(predicatesQuestionsAndDataComponentsDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, [])

    def subtechniqueSelected(self, *args):
        deleteText(subtechniqueDescriptionText)
        deleteText(techniquePlatformsText)
        deleteText(techniqueCapecIdText)
        dataComponentsListBox.delete(0, dataComponentsListBox.size())
        for item in dcInterctionRuleTreeView.get_children():
            dcInterctionRuleTreeView.delete(item)
        entitiesListBox.delete(0, entitiesListBox.size())
        questionsListBox.delete(0, questionsListBox.size())
        questionsIrListBox.delete(0, questionsIrListBox.size())
        if subtechniqueVar.get() == '':
            return
        # Display Subtechnique description
        subtechniqueID = subtechniqueVar.get().split(' ')[0] # Extract the ID that is the first part of the string
        subtechniqueDescription, subtechniquePlatforms = getTechniqueDetails(attackStix, subtechniqueID)
        insertText(subtechniqueDescriptionText, subtechniqueDescription)
        platforms = ''
        for platform in subtechniquePlatforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, subtechniqueID)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(subtechniqueID, relationshipsDF, dataComponentsListBox)
        entitiesInSubtechnique, foundEntitiesAndSynonyms = findEntitiesInText(subtechniqueDescription, entitiesDF)
        # Highlight in the description entities and their synonyms
        highlight(subtechniqueDescriptionText, foundEntitiesAndSynonyms, SUBTECHNIQUE_HIGHLIGHT)
        updateEntities(predicatesQuestionsAndDataComponentsDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique)

    # When a Data Component is selected, display interaction rules mapped to it
    def dataComponentSelected(event):
        selectedDataComponent = dataComponentsListBox.get(ANCHOR)
        for item in dcInterctionRuleTreeView.get_children():
            dcInterctionRuleTreeView.delete(item)
        if selectedDataComponent != '':
            updateDcInteractionRules(selectedDataComponent, predicatesQuestionsAndDataComponentsDF, dcInterctionRuleTreeView)

    # When an interaction rules is double-clicked, copy it to the SIR construction area
    def dcIrDoubleClicked(event):
        selectedIR = dcInterctionRuleTreeView.focus()
        if selectedIR != '':
            ir = dcInterctionRuleTreeView.item(selectedIR, "values")[1]
            irConstructionText.insert(END, ir+'\n')

    # When an entity is selected, display questions mapped to it
    def entitySelected(event):
        selectedEntity = entitiesListBox.get(ANCHOR)
        # Remove synonyms from selected entity's name
        bracketIndex = selectedEntity.find(' (')
        if bracketIndex != -1:
            selectedEntity = selectedEntity[:bracketIndex]
        questionsListBox.delete(0, questionsListBox.size())
        if selectedEntity != '':
            updateQuestions(selectedEntity, predicatesQuestionsAndDataComponentsDF, questionsListBox)

    # When a question is selected, display interaction rules mapped to it
    def questionSelected(event):
        selectedQuestion = questionsListBox.get(ANCHOR)
        questionsIrListBox.delete(0, questionsIrListBox.size())
        if selectedQuestion != '':
            updateQuestionsIr(selectedQuestion, predicatesQuestionsAndDataComponentsDF, questionsIrListBox)

    # When an interaction rules is double-clicked, copy it to the SIR construction area
    def questionIrDoubleClicked(event):
        selectedIR = questionsIrListBox.get(ANCHOR)
        if selectedIR != '':
            irConstructionText.insert(END, selectedIR+'\n')

    root = tkinter.Tk()
    root.title("SIRGen - A Decision-Support Tool For Generating New Sets of Interaction Rules From MITRE ATT&CK Techniques")

    # Add a grid
    mainframe = Frame(root)
    mainframe.grid(column=0, row=0, columnspan=10, rowspan=20, sticky=(N, W, E, S))
    mainframe.columnconfigure(0, weight=1)
    mainframe.rowconfigure(0, weight=1)
    mainframe.pack(pady=20, padx=20)
    fontTuple = ("Times new roman", 11, "normal")

    tactics = buildTacticList(attackStix)
    tacticVar = StringVar(root)
    techniqueVar = StringVar(root)
    subtechniqueVar = StringVar(root)
    Label(mainframe, text="Select a Tactic: ", height=2).grid(row=1, column=1)
    tacticCombo = ttk.Combobox(mainframe, value=(tactics), width= 50, state='readonly', textvariable=tacticVar)
    tacticCombo.grid(row=1, column=2, columnspan=3, padx=10, pady=2, sticky='w')
    Label(mainframe, text="Tactic Description:", height=2).grid(row=2, column=1, sticky=W)
    tacticDescriptionText = Text(mainframe, height=10, width = 76, padx=5, pady=5, wrap=WORD)
    tacticDescriptionScroll = Scrollbar(mainframe)
    tacticDescriptionText.configure(yscrollcommand=tacticDescriptionScroll.set, font = fontTuple, state='disabled')
    tacticDescriptionText.grid(row=3, column=1, columnspan=4, rowspan=7)
    tacticDescriptionScroll.config(command=tacticDescriptionText.yview)
    tacticDescriptionScroll.grid(row=3, column=5, columnspan=1, rowspan=7, sticky='ENS')
    tacticVar.trace_add('write', tacticSelected)

    Label(mainframe, text="Select a Technique: ", height=2).grid(row=10, column=1)
    techniqueCombo = ttk.Combobox(mainframe, state='readonly', width=50, textvariable=techniqueVar)
    techniqueCombo.grid(row=10, column=2, columnspan=3, padx=10, pady=2, sticky='w')
    Label(mainframe, text="Technique Description:", height=2).grid(row=11, column=1, sticky=W)
    techniqueDescriptionText = Text(mainframe, height=11, width = 76, padx=2, pady=2, wrap=WORD)
    techniqueDescriptionScroll = Scrollbar(mainframe)
    techniqueDescriptionText.configure(yscrollcommand=techniqueDescriptionScroll.set, font = fontTuple, state='disabled')
    techniqueDescriptionText.grid(row=12, column=1, columnspan=4, rowspan=5)
    techniqueDescriptionScroll.config(command=techniqueDescriptionText.yview)
    techniqueDescriptionScroll.grid(row=12, column=5, columnspan=1, rowspan=5, sticky='ENS')
    techniqueVar.trace_add('write', techniqueSelected)

    Label(mainframe, text="Select a Subtechnique: ", height=2).grid(row=17, column=1)
    subtechniqueCombo = ttk.Combobox(mainframe, width= 50, state='readonly', textvariable=subtechniqueVar)
    subtechniqueCombo.grid(row=17, column=2, columnspan=3, padx=10, pady=2, sticky='w')
    Label(mainframe, text="Sub-technique Description:", height=2).grid(row=18, column=1, sticky=W)
    subtechniqueDescriptionText = Text(mainframe, height=11, width = 76, padx=2, pady=2, wrap=WORD)
    subtechniqueDescriptionScroll = Scrollbar(mainframe)
    subtechniqueDescriptionText.configure(yscrollcommand=subtechniqueDescriptionScroll.set, font=fontTuple, state='disabled')
    subtechniqueDescriptionText.grid(row=19, column=1, columnspan=4, rowspan=5)
    subtechniqueDescriptionScroll.config(command=subtechniqueDescriptionText.yview)
    subtechniqueDescriptionScroll.grid(row=19, column=5, columnspan=1, rowspan=5, sticky='ENS')
    subtechniqueVar.trace_add('write', subtechniqueSelected)

    Label(mainframe, text="Platforms: ", height=2).grid(row=24, column=1)
    techniquePlatformsText = Text(mainframe, height=1, width=50, padx=2, pady=2, wrap=WORD)
    techniquePlatformsText.grid(row=24, column=2, columnspan=2, rowspan=1)
    techniquePlatformsText.configure(font = fontTuple, state='disabled')
    Label(mainframe, text="CAPEC ID: ", height=2).grid(row=25, column=1)
    techniqueCapecIdText = Text(mainframe, height=1, width=50, padx=2, pady=2, wrap=WORD)
    techniqueCapecIdText.grid(row=25, column=2, columnspan=2, rowspan=1)
    techniqueCapecIdText.configure(font = fontTuple, fg= 'blue', cursor='trek', state='disabled')

    Label(mainframe, text="  ").grid(row=1, column=6) # Filler column

    Label(mainframe, text="Technique/Sub-technique Data Components:", height=2).grid(row=1, column=7, sticky=W)
    dataComponentsListBox = Listbox(mainframe, height=11, width=88)
    dataComponentsScroll = Scrollbar(mainframe)
    dataComponentsListBox.configure(yscrollcommand=dataComponentsScroll.set, font = fontTuple)
    dataComponentsListBox.grid(row=2, column=7, columnspan=4, rowspan=8)
    dataComponentsScroll.config(command=dataComponentsListBox.yview)
    dataComponentsScroll.grid(row=2, column=11, columnspan=1, rowspan=8, sticky='ENS')
    dataComponentsListBox.bind('<<ListboxSelect>>', dataComponentSelected)

    Label(mainframe, text="Interaction rules realted to the selected Data Component:", height=2).grid(row=10, column=7, sticky=W)
    dcInterctionRuleTreeView = ttk.Treeview(mainframe, column=(1, 2), show='headings')
    dcInterctionRuleTreeView.column(1, anchor=CENTER, width=320)
    dcInterctionRuleTreeView.column(2, anchor=CENTER, width=300)
    dcInterctionRuleTreeView.heading(1, text='Data Component', anchor=CENTER)
    dcInterctionRuleTreeView.heading(2, text='Interaction Rule', anchor=CENTER)
    dcInterctionRuleScroll = Scrollbar(mainframe)
    dcInterctionRuleTreeView.configure(yscrollcommand=dcInterctionRuleScroll.set)
    dcInterctionRuleTreeView.grid(row=11, column=7, columnspan=4, rowspan=6)
    dcInterctionRuleScroll.config(command=dcInterctionRuleTreeView.yview)
    dcInterctionRuleScroll.grid(row=11, column=11, columnspan=1, rowspan=6, sticky='ENS')
    dcInterctionRuleTreeView.bind("<Double-1>", dcIrDoubleClicked)

    Label(mainframe, text="Interaction rule construction area:", height=2).grid(row=17, column=7, sticky=W)
    irConstructionText = Text(mainframe, height=13, width = 88, padx=2, pady=2, wrap=WORD)
    irConstructionScroll = Scrollbar(mainframe)
    irConstructionText.configure(yscrollcommand=irConstructionScroll.set, font=fontTuple)
    irConstructionText.grid(row=18, column=7, columnspan=4, rowspan=6)
    irConstructionScroll.config(command=irConstructionText.yview)
    irConstructionScroll.grid(row=18, column=11, columnspan=1, rowspan=6, sticky='ENS')

    Label(mainframe, text="  ").grid(row=1, column=12) # Filler column

    Label(mainframe, text="Attack entities (entities found in the TTP descriptions are highlighted):", height=2).grid(row=1, column=13, sticky=W)
    entitiesListBox = Listbox(mainframe, height=11, width=85)
    entitiesScroll = Scrollbar(mainframe)
    entitiesListBox.configure(yscrollcommand=entitiesScroll.set, font = fontTuple)
    entitiesListBox.grid(row=2, column=13, columnspan=4, rowspan=8)
    entitiesScroll.config(command=entitiesListBox.yview)
    entitiesScroll.grid(row=2, column=17, columnspan=1, rowspan=8, sticky='ENS')
    entitiesListBox.bind('<<ListboxSelect>>', entitySelected)

    Label(mainframe, text="Guided questions:", height=2).grid(row=10, column=13, sticky=W)
    questionsListBox = Listbox(mainframe, height=13, width=85)
    questionsScroll = Scrollbar(mainframe)
    questionsListBox.configure(yscrollcommand=questionsScroll.set, font = fontTuple)
    questionsListBox.grid(row=11, column=13, columnspan=4, rowspan=6)
    questionsScroll.config(command=questionsListBox.yview)
    questionsScroll.grid(row=11, column=17, columnspan=1, rowspan=6, sticky='ENS')
    questionsListBox.bind('<<ListboxSelect>>', questionSelected)

    Label(mainframe, text="Interaction rules realted to the selected question:", height=2).grid(row=17, column=13, sticky=W)
    questionsIrListBox = Listbox(mainframe, height=13, width=85)
    questionsIrScroll = Scrollbar(mainframe)
    questionsIrListBox.configure(yscrollcommand=questionsIrScroll.set, font = fontTuple)
    questionsIrListBox.grid(row=18, column=13, columnspan=4, rowspan=6)
    questionsIrScroll.config(command=questionsIrListBox.yview)
    questionsIrScroll.grid(row=18, column=17, columnspan=1, rowspan=6, sticky='ENS')
    questionsIrListBox.bind("<Double-1>", questionIrDoubleClicked)

    style = ttk.Style()
    style.theme_use("clam")
    style.map("Treeview")

    root.mainloop()

# The following methods build Tactics, Techniques and Sub-techniques using ATT&CK-STIX json
def buildTacticList(attackStix):
    tacticsList = []
    filter = [
        Filter('type', '=', 'x-mitre-matrix'),
    ]
    matrix = attackStix.query(filter)
    for tactic_id in matrix[0]['tactic_refs']:
        tactic = attackStix.get(tactic_id)
        tacticsList.append(tactic['external_references'][0]['external_id'] + ' ' + tactic['name'])
    return tacticsList

def getTacticField(attackStix, tacticId, fieldName):
    filter = [
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('external_references.external_id', '=', tacticId)
    ]
    tactic = attackStix.query(filter)
    return tactic[0][fieldName]

def buildTechniqueList(attackStix, tacticId):
    tacticShortName = getTacticField(attackStix, tacticId, 'x_mitre_shortname')
    techniquesList = []
    # Techniques map into tactics by use of their kill_chain_phases property.
    # Where the kill_chain_name is mitre-attack (for enterprise), the phase_name corresponds to the x_mitre_shortname property of an x-mitre-tactic object.
    filter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
        Filter('kill_chain_phases.phase_name', '=', tacticShortName),
        Filter('x_mitre_is_subtechnique', '=', False)
    ]
    techniques = attackStix.query(filter)
    for technique in techniques:
        techniquesList.append(technique['external_references'][0]['external_id'] + ' ' + technique['name'])

    techniquesList.sort()
    return techniquesList

def getTechniqueDetails(attackStix, techniqueId):
    filter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', techniqueId)
    ]
    technique = attackStix.query(filter)
    return technique[0]['description'], technique[0]['x_mitre_platforms']

def buildSubtechniqueList(attackStix, techniqueId):
    subtechniquesList = []
    filter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', 'contains', techniqueId),
        Filter('x_mitre_is_subtechnique', '=', True)
    ]
    subtechniques = attackStix.query(filter)
    for subtechnique in subtechniques:
        subtechniquesList.append(subtechnique['external_references'][0]['external_id'] + ' ' + subtechnique['name'])

    subtechniquesList.sort()
    return subtechniquesList


# Find CAPEC-ID related to a Technique
def findCapecIdAndUrl(attackStix, techniqueId):
    capecID = ''
    capecURL = ''
    # Retrieve the Technique
    filter = [
        Filter('type', '=', 'attack-pattern'),
        #Filter('name', '=', techniqueName)
        Filter('external_references.external_id', '=', techniqueId)
    ]
    technique = attackStix.query(filter)
    for ext_ref in technique[0].external_references:
        if ext_ref.source_name == 'capec':
            capecID = ext_ref.external_id
            capecURL = ext_ref.url

    return capecID, capecURL

# Helper method to clear a text box
def deleteText(textWidget):
    textWidget.configure(state='normal')
    textWidget.delete('1.0', END)
    textWidget.configure(state='disabled')

# Helper method to insert text in text box
def insertText(textWidget, text):
    textWidget.configure(state='normal')
    textWidget.insert(1.0, text)
    textWidget.configure(state='disabled')

def searchListById(list, Id):
    for elem in list:
        if elem.id == Id:
            return elem
    return None

# Highlight the given list of words in textWidget
def highlight(textWidget, words, color):
    if "highlight" in textWidget.tag_names():
        textWidget.tag_delete("highlight")
    for word in words:
        if word == '':  # Ignore empty words
            continue
        highlightStart = "1.0"
        while True:
            highlightStart = textWidget.search(word, highlightStart, nocase=1, stopindex='end')
            if highlightStart == '':
                break
            highlightEnd = textWidget.index("%s+%dc" % (highlightStart, len(word)))
            textWidget.tag_add("highlight", highlightStart, highlightEnd)
            textWidget.tag_config("highlight", background=color)
            highlightStart = highlightEnd

# Build list of Data Components for given Technique (or Sub-technique)
def updateDataComponents(techniqueID, relationshipsDF, dcListBox):
    dataComponents = []
    for i in relationshipsDF.index:
        if relationshipsDF["technique_id"][i] == techniqueID and str(relationshipsDF["source_data_element"][i]) != 'nan':
            dataComponents.append(relationshipsDF["source_data_element"][i] + ' ' + relationshipsDF["relationship"][i] + ' ' + relationshipsDF["target_data_element"][i])
    for i in range(len(dataComponents)):
        dcListBox.insert(i, dataComponents[i])

def updateDcInteractionRules(dataComponent, predicatesDF, dcIrTreeView):
    for i in predicatesDF.index:
        if not pandas.isna(predicatesDF["DataComponent"][i]) and predicatesDF["DataComponent"][i].startswith(dataComponent):
            lineTag = 'line'+str(len(dcIrTreeView.get_children()) % 2)
            dcIrTreeView.insert('', 'end', text="1", values=(predicatesDF["DataComponent"][i], predicatesDF["Predicate"][i]), tag=lineTag)
    dcIrTreeView.tag_configure('line0', background='gray') # This highlights each second line, but the highlight is not visible in every monitor

# Build list of entities (and their synonyms)
# Highlight entities that appear in the description of selected Tactic/Technique/Sub-technique
def updateEntities(predicatesDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique):
    entities = []
    for i in predicatesDF.index:
        if  not (predicatesDF["Entity"][i] in entities) and str(predicatesDF["Question"][i]) != '' and str(predicatesDF["Predicate"][i]) != '':
            entities.append(predicatesDF["Entity"][i])
    for i in range(len(entities)):
        if pandas.isna(entities[i]):
            continue
        # Append synonyms to entity name
        entityRow = entitiesDF.loc[entitiesDF["Entity"] == entities[i]]
        synonyms = ''
        if entityRow.size != 0:  # If a question was attached to a non-existing entity, the 'entity' will not be found
            synonyms = entityRow["Synonyms"].item()
        entity = entities[i]
        if synonyms != '':
            entity = entity + ' (' + synonyms + ')'
        entitiesListBox.insert(i, entity)
        if entities[i] in entitiesInTactic:
            entitiesListBox.itemconfig(i, bg=TACTIC_HIGHLIGHT)
        if entities[i] in entitiesInTechnique:
            entitiesListBox.itemconfig(i, bg=TECHNIQUE_HIGHLIGHT)
        if entities[i] in entitiesInSubtechnique:
            entitiesListBox.itemconfig(i, bg=SUBTECHNIQUE_HIGHLIGHT)

# Build list of questions for the selected entitiy
def updateQuestions(selectedEntity, predicatesDF, questionsListBox):
    questions = []
    for i in predicatesDF.index:
        if predicatesDF["Entity"][i] == selectedEntity and str(predicatesDF["Question"][i]) != '' \
                and str(predicatesDF["Predicate"][i]) != '' and predicatesDF["Question"][i] not in questions:
            questions.append(predicatesDF["Question"][i])
    for i in range(len(questions)):
        if not pandas.isna(questions[i]):
            # ToDo: should wrap the long questions, but ListBox doesn't enable this, and adding \n with wrap() doesn't help
            #questionsListBox.insert(i, wrap(questions[i], lenght=85))
            questionsListBox.insert(i, questions[i])

# Build list of interaction rules for the selected question
def updateQuestionsIr(selectedQuestion, predicatesDF, questionsIrListBox):
    questionIrs = []
    for i in predicatesDF.index:
        if predicatesDF["Question"][i] == selectedQuestion and str(predicatesDF["Predicate"][i]) != '':
            questionIrs.append(predicatesDF["Predicate"][i])
    for i in range(len(questionIrs)):
        questionsIrListBox.insert(i, questionIrs[i])

# Find if an entity or one of its synonyms appear in the given text
def findEntitiesInText(text, entitiesDF):
    foundEntities = []
    foundEntitiesAndSynonyms = []
    for i in entitiesDF.index:
        if entitiesDF["Entity"][i] in text or (entitiesDF["Synonyms"][i] != '' and any(entity in text for entity in entitiesDF["Synonyms"][i].split(', '))):
            foundEntities.append(entitiesDF["Entity"][i])
            foundEntitiesAndSynonyms.append(entitiesDF["Entity"][i])
            for entity in entitiesDF["Synonyms"][i].split(', '):
                foundEntitiesAndSynonyms.append(entity)
    return foundEntities, foundEntitiesAndSynonyms


if __name__ == '__main__':
    # enterprise-attack.json can be found at: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack
    # We will use this data structure also to find connections between Techniques and CAPEC
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json").json()
    attackStix = MemoryStore(stix_data=stix_json["objects"])
    #printTacticTecniqueFromStix(attackStix)

    # Read relationships, which include Data Components, from CSV to DataFrame
    # Source of "techniques_to_relationships_mapping.csv":https://github.com/mitre-attack/attack-datasources/tree/main/docs
    relationshipsFilePath = "file:techniques_to_relationships_mapping.csv"  # Read from local path
    # Reading directly from github (the following line) doesn't work (read_csv throws exception)
    #relationshipsFilePath = "https://raw.githubusercontent.com/mitre-attack/attack-datasources/main/docs/techniques_to_relationships_mapping.csv"
    relationshipsDF = pandas.read_csv(relationshipsFilePath, keep_default_na=False)
    # Read mapping between predicates, questions and data components
    predicatesQuestionsAndDataComponentsDF = pandas.read_csv("file:SIRGenQuestionsAndDataComponents.csv")
    # Read list of attack ontology entities and their synonyms
    entitiesDF = pandas.read_csv("file:EntitiesAndSynonyms.csv", keep_default_na=False)
    displayTTP(attackStix, relationshipsDF, predicatesQuestionsAndDataComponentsDF, entitiesDF)
