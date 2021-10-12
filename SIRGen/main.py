from pyattck import Attck # https://pypi.org/project/pyattck/
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
from stix2 import MemoryStore, Filter
import requests
import pandas
import tkinter
from tkinter import *
from tkinter import ttk
import webbrowser
import textwrap

# Opens given URL in a browser's tab
def openURL(url):
    webbrowser.open_new(url)

# Wraps the given string by every length characters
def wrap(string, lenght=40):
    return '\n'.join(textwrap.wrap(string, lenght))

# Helper method for testing data of ATT&CK STIX
def printMitreTacticTecnique(attackdata):
    # build_dataframes brings everything and takes a long time
    #dataframes = attackToExcel.build_dataframes(attackdata, "enterprise-attack")

    # Get Tactics
    tatics_data = stixToDf.tacticsToDf(attackdata, "enterprise-attack")
    tactics_df = tatics_data["tactics"]
    tactics = []
    for i in tactics_df.index:
        tactics.append(tactics_df["ID"][i] + ' ' + tactics_df["name"][i])

    # get Pandas DataFrames for techniques, associated relationships, and citations
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    techniques_df = techniques_data["techniques"]

    # show T1102 and sub-techniques of T1102
    print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])

# Helper method for testing data of ATT&CK from pyattck
def printTacticTecnique(attack):
    for tactic in attack.enterprise.tactics:
        print(tactic.id + ' ' + tactic.name)
        print(tactic.description)

    for technique in attack.enterprise.techniques:
        print(technique.id + ' ' + technique.name)
        print('Description: ' + technique.description)
        print('Platforms: ')
        for platform in technique.platforms:
            print(platform + ' ')
        print('Data Components: ')
        for detection in technique.possible_detections:
            ds = detection['data_source']
            print(ds['source_data_element'] + ' ' + ds['relationship'] + ' ' + ds['target_data_element'])

# Main GUI method
def displayTTP(attack, relationshipsDF, attackStix, dcToIrDF, questionsToIrDF, entitiesDF):
    # Methods for selection events
    def tacticSelected(self, *args):
        deleteText(tacticDescriptionText)
        if tacticVar.get() == '':
            return
        # Display Tactic description
        tacticID = tacticVar.get().split(' ')[0] # Extract the ID that is the first part of the string
        global selectedTactic
        selectedTactic = searchListById(attack.enterprise.tactics, tacticID)
        insertText(tacticDescriptionText, "Selected Tactic: " + selectedTactic.id + ' ' + selectedTactic.name + "\n" + selectedTactic.description)
        # Update Technique drop-down
        techniques = buildTechniqueList(selectedTactic)
        techniqueCombo.config(value=techniques)
        techniqueCombo.set('')
        subtechniqueCombo.set('')
        global entitiesInTactic  # Entities found in the description of selected Tactic
        entitiesInTactic = findEntitiesInText(selectedTactic.description, entitiesDF)

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
        technique = searchListById(selectedTactic.techniques, techniqueID)
        insertText(techniqueDescriptionText, "Selected Technique: " + technique.id + ' ' + technique.name + "\n" + technique.description)

        # Update Subtechnique drop-down
        subtechniques = buildSubtechniqueList(technique, selectedTactic)
        subtechniqueCombo.config(value=subtechniques)
        subtechniqueCombo.set('')

        # Update platforms and CAPEC-ID
        platforms = ''
        for platform in technique.platforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, technique.name)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(techniqueID, relationshipsDF, dataComponentsListBox)
        global entitiesInTechnique # Entities found in the description of selected Technique
        entitiesInTechnique = findEntitiesInText(technique.description, entitiesDF)
        updateEntities(questionsToIrDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, [])

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
        technique = searchListById(selectedTactic.techniques, subtechniqueID)
        insertText(subtechniqueDescriptionText, "Selected Subtechnique: " + technique.id + ' ' + technique.name + "\n" + technique.description)
        platforms = ''
        for platform in technique.platforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, technique.name)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(subtechniqueID, relationshipsDF, dataComponentsListBox)
        entitiesInSubtechnique = findEntitiesInText(technique.description, entitiesDF)
        updateEntities(questionsToIrDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique)

    # When a Data Component is selected, display interaction rules mapped to it
    def dataComponentSelected(event):
        selectedDataComponent = dataComponentsListBox.get(ANCHOR)
        for item in dcInterctionRuleTreeView.get_children():
            dcInterctionRuleTreeView.delete(item)
        if selectedDataComponent != '':
            updateDcInteractionRules(selectedDataComponent, dcToIrDF, dcInterctionRuleTreeView)

    # When an interaction rules is double-clicked, copy it to the SIR construction area
    def dcIrDoubleClicked(event):
        selectedIR = dcInterctionRuleTreeView.focus()
        if selectedIR != '':
            ir = dcInterctionRuleTreeView.item(selectedIR, "values")[1]
            irConstructionText.insert(END, ir+'\n')

    # When an entity is selected, display questions mapped to it
    def entitySelected(event):
        selectedEntity = entitiesListBox.get(ANCHOR)
        questionsListBox.delete(0, questionsListBox.size())
        if selectedEntity != '':
            updateQuestions(selectedEntity, questionsToIrDF, questionsListBox)

    # When a question is selected, display interaction rules mapped to it
    def questionSelected(event):
        selectedQuestion = questionsListBox.get(ANCHOR)
        questionsIrListBox.delete(0, questionsIrListBox.size())
        if selectedQuestion != '':
            updateQuestionsIr(selectedQuestion, questionsToIrDF, questionsIrListBox)

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

    tactics = buildTacticList(attack)
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

def buildTacticList(attack):
    tactics = []
    for tactic in attack.enterprise.tactics:
        tactics.append(tactic.id + ' ' + tactic.name)
    return  tactics

def buildTechniqueList(tactic):
    techniques = []
    for technique in tactic.techniques:
        if not technique.subtechnique:
            techniques.append(technique.id + ' ' + technique.name)
    techniques.sort()
    return techniques

def buildSubtechniqueList(technique, tactic):
    subtechniques = []
    for tech in tactic.techniques:
        if technique.id in tech.id and technique.id != tech.id:
            subtechniques.append(tech.id + ' ' + tech.name)
    subtechniques.sort()
    return subtechniques

# Technique object doesn't include CAPEC-ID; use ATT&CK STIX Data to find it
def findCapecIdAndUrl(attackStix, techniqueName):
    capecID = ''
    capecURL = ''
    # Retrieve the Technique
    filter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', techniqueName)
        #Filter('external_references.external_id', '=', techniqueId) This is an alternative, filter by Technique ID
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

# Build list of Data Components for given Technique (or Sub-technique)
def updateDataComponents(techniqueID, relationshipsDF, dcListBox):
    dataComponents = []
    for i in relationshipsDF.index:
        if relationshipsDF["technique_id"][i] == techniqueID and str(relationshipsDF["source_data_element"][i]) != 'nan':
            dataComponents.append(relationshipsDF["source_data_element"][i] + ' ' + relationshipsDF["relationship"][i] + ' ' + relationshipsDF["target_data_element"][i])
    for i in range(len(dataComponents)):
        dcListBox.insert(i, dataComponents[i])

def updateDcInteractionRules(dataComponent, dcToIrDF, dcIrTreeView):
    for i in dcToIrDF.index:
        if dcToIrDF["DataComponent"][i].startswith(dataComponent):
            lineTag = 'line'+str(len(dcIrTreeView.get_children()) % 2)
            dcIrTreeView.insert('', 'end', text="1", values=(dcToIrDF["DataComponent"][i], dcToIrDF["InteractionRule"][i]), tag=lineTag)
    dcIrTreeView.tag_configure('line0', background='gray') # This should color each second line, but doesn't work...

# Build list of entities and highlight entities that appear in the description of selected Tactic/Technique/Sub-technique
def updateEntities(questionsToIrDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique):
    entities = []
    for i in questionsToIrDF.index:
        if  not (questionsToIrDF["OntologyEntity"][i] in entities) and str(questionsToIrDF["Question"][i]) != '' and str(questionsToIrDF["NormalizedIR"][i]) != '':
            entities.append(questionsToIrDF["OntologyEntity"][i])
    for i in range(len(entities)):
        entitiesListBox.insert(i, entities[i])
        if entities[i] in entitiesInTactic:
            entitiesListBox.itemconfig(i, bg='#98FB98')
        if entities[i] in entitiesInTechnique:
            entitiesListBox.itemconfig(i, bg='#54FF9F')
        if entities[i] in entitiesInSubtechnique:
            entitiesListBox.itemconfig(i, bg='#00CD66')

# Build list of questions for the selected entitiy
def updateQuestions(selectedEntity, questionsToIrDF, questionsListBox):
    questions = []
    for i in questionsToIrDF.index:
        if questionsToIrDF["OntologyEntity"][i] == selectedEntity and str(questionsToIrDF["Question"][i]) != '' and str(questionsToIrDF["NormalizedIR"][i]) != '':
            questions.append(questionsToIrDF["Question"][i])
    for i in range(len(questions)):
        # ToDo: should wrap the long questions, but ListBox doesn't enable this, and adding \n with wrap() doesn't help
        questionsListBox.insert(i, wrap(questions[i], lenght=85))

# Build list of interaction rules for the selected question
def updateQuestionsIr(selectedQuestion, questionsToIrDF, questionsIrListBox):
    questionIrs = []
    for i in questionsToIrDF.index:
        if questionsToIrDF["Question"][i] == selectedQuestion and str(questionsToIrDF["NormalizedIR"][i]) != '':
            questionIrs.append(questionsToIrDF["NormalizedIR"][i])
    for i in range(len(questionIrs)):
        questionsIrListBox.insert(i, questionIrs[i])

# Find if an entity or one of its sysnonyms appear in the given text
def findEntitiesInText(text, entitiesDF):
    foundEntities = []
    for i in entitiesDF.index:
        if entitiesDF["Entity"][i] in text or (entitiesDF["Synonyms"][i] != '' and any(entity in text for entity in entitiesDF["Synonyms"][i].split(' '))):
            foundEntities.append(entitiesDF["Entity"][i])
    return foundEntities


if __name__ == '__main__':
    # Download and parse ATT&CK STIX data
    #attackdata = attackToExcel.get_stix_data("enterprise-attack")
    #printMitreTacticTecnique(attackdata)
    attack = Attck() # Build the ATT&CK data structure from pyattck, which is easier to handle than get_stix_data()

    # enterprise-attack.json can be found also at: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack
    # We will use this data structure to find connections between Techniques and CAPEC
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json").json()
    attackStix = MemoryStore(stix_data=stix_json["objects"])

    # Read relationships, which include Data Components, from CSV to DataFrame
    # ToDo: find out the source of "techniques_to_relationships_mapping.csv" and read from there
    relationshipsDF = pandas.read_csv("file:techniques_to_relationships_mapping.csv", keep_default_na=False)
    # Read mapping between Data Components and interaction rules
    dataComponentsToInteractionRulesDF = pandas.read_csv("file:DataComponentsToInteractionRulesMapping.csv")
    # Read mapping between questionss and interaction rules
    questionsToInteractionRulesDF = pandas.read_csv("file:IRGenQuestions.csv", keep_default_na=False)
    # Read list of attack ontology entities and their synonyms
    entitiesDF = pandas.read_csv("file:EntitiesAndSynonyms.csv", keep_default_na=False)
    #printTacticTecnique(attack)
    displayTTP(attack, relationshipsDF, attackStix,dataComponentsToInteractionRulesDF, questionsToInteractionRulesDF, entitiesDF)
