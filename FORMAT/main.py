from stix2 import MemoryStore, Filter
import requests
import pandas
import numpy
import tkinter
from tkinter import *
from tkinter import ttk
import webbrowser
import textwrap
from langchain_community.llms import GPT4All

TACTIC_HIGHLIGHT = '#98FB98'
TECHNIQUE_HIGHLIGHT = '#54FF9F'
SUBTECHNIQUE_HIGHLIGHT = '#00CD66'
DC_HIGHLIGHT = 'cyan'

# Opens given URL in a browser's tab
def openURL(url):
    webbrowser.open_new(url)

# Wraps the given string by every length characters
def wrap(string, length=40):
    return '\n'.join(textwrap.wrap(string, length))

# Helper method for testing data of ATT&CK STIX (brought from json)
def printTacticTechniqueFromStix(attackStix):
    # Get Tactics
    tacticFilter = [
        Filter('type', '=', 'x-mitre-tactic'),
    ]
    tactics = attackStix.query(tacticFilter)
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
    sampleFilter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
        Filter('kill_chain_phases.phase_name', '=', 'collection')
    ]
    techniques = attackStix.query(sampleFilter)
    for technique in techniques:
        print(technique['external_references'][0]['external_id'] + ' ' + technique['name'])
        print(technique['description'])

    techniques = buildTechniqueList(attackStix, tacticId)
    techniqueID = techniques[0].split(' ')[0]  # Extract the ID that is the first part of the string
    techniqueDescription, permissionsRequired, systemRequirements, techniquePlatforms = \
        getTechniqueDetails(attackStix, systemRequirements, techniquePlatforms, techniqueID)
    print(techniqueDescription, techniquePlatforms)
    subtechniques = buildSubtechniqueList(attackStix, techniqueID)
    subtechniqueID = subtechniques[0].split(' ')[0]  # Extract the ID that is the first part of the string
    subtechniqueDescription, permissionsRequired, systemRequirements, subtechniquePlatforms = \
        getTechniqueDetails(attackStix, subtechniqueID)
    print(subtechniqueDescription, permissionsRequired, systemRequirements, subtechniquePlatforms)

# Build IR head from Technique name
def buildIrHead(techniqueName):
    irHead = techniqueName.translate(str.maketrans("", "", " -/()"))  # Remove spaces and other illegal characters
    irHead = irHead[0].lower() + irHead[1:]  # Lowercase the first letter
    return irHead

# Main GUI method
def displayTTP(attackStix, relationshipsDF, predicatesDF, entitiesDF):
    # Methods for selection events
    def tacticSelected(self, *args):
        deleteText(tacticDescriptionText)
        if tacticVar.get() == '':
            return
        # Display Tactic description
        tacticID = tacticVar.get().split(' ')[0]  # Extract the ID that is the first part of the string
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
        deleteText(permissionsRequiredText)
        deleteText(systemRequirementsText)
        deleteText(techniquePlatformsText)
        deleteText(techniqueCapecIdText)
        dataComponentsListBox.delete(0, dataComponentsListBox.size())
        for item in dcPredicateTreeView.get_children():
            dcPredicateTreeView.delete(item)
        entitiesListBox.delete(0, entitiesListBox.size())
        entitiesPredicatesListBox.delete(0, entitiesPredicatesListBox.size())
        irConstructionText.delete("1.0", "end")
        deleteText(syntaxText)
        if techniqueVar.get() == '':
            return
        # Display Technique description
        techniqueID = techniqueVar.get().split(' ')[0]  # Extract the ID, which is the first part of the string
        techniqueDescription, permissionsRequired, systemRequirements, techniquePlatforms = \
            getTechniqueDetails(attackStix, techniqueID)
        insertText(techniqueDescriptionText, techniqueDescription)

        # Update Subtechnique drop-down
        subtechniques = buildSubtechniqueList(attackStix, techniqueID)
        subtechniqueCombo.config(value=subtechniques)
        subtechniqueCombo.set('')

        # Update Permissions Required, System Requirements, Platforms and CAPEC-ID
        insertText(permissionsRequiredText, permissionsRequired)
        insertText(systemRequirementsText, systemRequirements)
        platforms = ''
        for platform in techniquePlatforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, techniqueID)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(techniqueID, relationshipsDF, predicatesDF, dataComponentsListBox)
        global entitiesInTechnique # Entities found in the description of selected Technique
        entitiesInTechnique, foundEntitiesAndSynonyms = findEntitiesInText(techniqueDescription, entitiesDF)
        # Highlight in the description entities and their synonyms
        highlight(techniqueDescriptionText, foundEntitiesAndSynonyms, TECHNIQUE_HIGHLIGHT)
        updateEntities(predicatesDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, [])

        techniqueName = techniqueVar.get()[techniqueVar.get().find(' ') + 1:]  # Extract the Technique name
        irHead = buildIrHead(techniqueName)
        irConstructionText.insert(END, irHead + '(' + ', '.join(entitiesInTechnique) + ') :-\n')

    def subtechniqueSelected(self, *args):
        deleteText(subtechniqueDescriptionText)
        deleteText(permissionsRequiredText)
        deleteText(systemRequirementsText)
        deleteText(techniquePlatformsText)
        deleteText(techniqueCapecIdText)
        dataComponentsListBox.delete(0, dataComponentsListBox.size())
        for item in dcPredicateTreeView.get_children():
            dcPredicateTreeView.delete(item)
        entitiesListBox.delete(0, entitiesListBox.size())
        entitiesPredicatesListBox.delete(0, entitiesPredicatesListBox.size())
        irConstructionText.delete("1.0", "end")
        if subtechniqueVar.get() == '':
            return
        # Display Subtechnique description
        subtechniqueID = subtechniqueVar.get().split(' ')[0]  # Extract the ID that is the first part of the string
        subtechniqueDescription, permissionsRequired, systemRequirements, subtechniquePlatforms = \
            getTechniqueDetails(attackStix, subtechniqueID)
        insertText(subtechniqueDescriptionText, subtechniqueDescription)

        # Update Permission Required, Platforms and CAPEC-ID
        insertText(permissionsRequiredText, permissionsRequired)
        insertText(systemRequirementsText, systemRequirements)
        platforms = ''
        for platform in subtechniquePlatforms:
            platforms += platform + ' '
        insertText(techniquePlatformsText, platforms)
        # Technique object doesn't include CAPEC-ID; we will bring it from ATT&CK STIX Data
        capecID, capecURL = findCapecIdAndUrl(attackStix, subtechniqueID)
        insertText(techniqueCapecIdText, capecID)
        techniqueCapecIdText.bind("<Button-1>", lambda e: openURL(capecURL))

        updateDataComponents(subtechniqueID, relationshipsDF, predicatesDF, dataComponentsListBox)
        entitiesInSubtechnique, foundEntitiesAndSynonyms = findEntitiesInText(subtechniqueDescription, entitiesDF)
        # Highlight in the description entities and their synonyms
        highlight(subtechniqueDescriptionText, foundEntitiesAndSynonyms, SUBTECHNIQUE_HIGHLIGHT)
        updateEntities(predicatesDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique)

        subtechniqueName = subtechniqueVar.get()[subtechniqueVar.get().find(' ') + 1:]  # Extract the Sub-technique name
        irHead = buildIrHead(subtechniqueName)
        irConstructionText.insert(END, irHead + '(' + ', '.join(entitiesInSubtechnique) + ') :-\n')

    # When a Data Component is selected, display interaction rules mapped to it
    def dataComponentSelected(event):
        selectedDataComponent = dataComponentsListBox.get(ANCHOR)
        for item in dcPredicateTreeView.get_children():
            dcPredicateTreeView.delete(item)
        if selectedDataComponent != '':
            updateDcInteractionRules(selectedDataComponent, predicatesDF, dcPredicateTreeView)

    # When an interaction rules is double-clicked, copy it to the IR construction area
    def dcIrDoubleClicked(event):
        selectedIR = dcPredicateTreeView.focus()
        if selectedIR != '':
            ir = dcPredicateTreeView.item(selectedIR, "values")[1]
            irConstructionText.insert(END, f'  {ir},\n')

    # When an entity is selected, display predicates mapped to it
    def entitySelected(event):
        selectedEntity = entitiesListBox.get(ANCHOR)
        # Remove synonyms from selected entity's name
        bracketIndex = selectedEntity.find(' (')
        if bracketIndex != -1:
            selectedEntity = selectedEntity[:bracketIndex]
        entitiesPredicatesListBox.delete(0, entitiesPredicatesListBox.size())
        if selectedEntity != '':
            updatePredicates(selectedEntity, predicatesDF, entitiesPredicatesListBox)

    # When a predicate is double-clicked, copy it to the IR construction area
    def entitiesPredicatesDoubleClicked(event):
        selectedPredicate = entitiesPredicatesListBox.get(ANCHOR)
        if selectedPredicate != '':
            irConstructionText.insert(END, f'  {selectedPredicate},\n')

    # Todo call LLM API
    # Use LLM to deduce relevant predicates from description
    def predicatesFromDescription():
        irConstructionText.insert(END, '  TBD: LLM selected predicates' + '\n')

    # Add user as attacker predicate
    def userAsAttacker():
        irConstructionText.insert(END, '  malicious(User),' + '\n')

    # Add relevant predicates for Permission Required
    def handlePermissionsRequired():
        permissionsRequired = permissionsRequiredText.get("1.0", "end-1c")
        if permissionsRequired == '':
            return
        irConstructionText.insert(END, '  hasAccount(User, Host, _Account),' + '\n')
        if permissionsRequired == 'Administrator':
            irConstructionText.insert(END, '  isAdmin(User, Host),' + '\n')

    # Todo call LLM API
    # Use LLM to deduce relevant predicates for System Requirements
    def handleSystemRequirements():
        systemRequirements = systemRequirementsText.get("1.0", "end-1c")
        if systemRequirements == '':
            return
        irConstructionText.insert(END, '  TBD: LLM selected predicates' + '\n')

    # Add relevant predicates for Platforms
    def handlePlatforms():
        platforms = techniquePlatformsText.get("1.0", "end-1c")
        if platforms == '' or platforms.strip() == 'PRE':
            return
        platformList = platforms.split()
        if len(platformList) == 1:
            platform = platformList[0]
            platform = platform[0].lower() + platform[1:]  # Lowercase the first letter
            irConstructionText.insert(END, f'  hostPlatform(Host, {platform}),' + '\n')
        else:
            irConstructionText.insert(END,\
                f'  hostPlatform(Host, platform), /* Duplicate the IR and in each instance use a platform from the list */' + '\n')

    # Use LLM to validate IR syntax
    def validateIrSyntax():
        deleteText(syntaxText)
        syntaxValidationOutput = llm.invoke("The following rule is written in Datalog: " +
            irConstructionText.get("1.0", "end-1c") + syntaxValidationPrompt)
        insertText(syntaxText, syntaxValidationOutput)

    root = tkinter.Tk()
    root.title("FORMAT - Forming Operational (Interaction) Rules for MITRE ATT&CK Techniques")

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
    tacticDescriptionText.configure(yscrollcommand=tacticDescriptionScroll.set, font=fontTuple, state='disabled')
    tacticDescriptionText.grid(row=3, column=1, columnspan=4, rowspan=7)
    tacticDescriptionScroll.config(command=tacticDescriptionText.yview)
    tacticDescriptionScroll.grid(row=3, column=5, columnspan=1, rowspan=7, sticky='ENS')
    tacticVar.trace_add('write', tacticSelected)

    Label(mainframe, text="Select a Technique: ", height=2).grid(row=10, column=1)
    techniqueCombo = ttk.Combobox(mainframe, state='readonly', width=50, textvariable=techniqueVar)
    techniqueCombo.grid(row=10, column=2, columnspan=3, padx=10, pady=2, sticky='w')
    Label(mainframe, text="Technique Description:", height=2).grid(row=11, column=1, sticky=W)
    techniqueDescriptionText = Text(mainframe, height=11, width=76, padx=2, pady=2, wrap=WORD)
    techniqueDescriptionScroll = Scrollbar(mainframe)
    techniqueDescriptionText.configure(yscrollcommand=techniqueDescriptionScroll.set, font=fontTuple, state='disabled')
    techniqueDescriptionText.grid(row=12, column=1, columnspan=4, rowspan=5)
    techniqueDescriptionScroll.config(command=techniqueDescriptionText.yview)
    techniqueDescriptionScroll.grid(row=12, column=5, columnspan=1, rowspan=5, sticky='ENS')
    techniqueVar.trace_add('write', techniqueSelected)

    Label(mainframe, text="Select a Subtechnique: ", height=2).grid(row=17, column=1)
    subtechniqueCombo = ttk.Combobox(mainframe, width=50, state='readonly', textvariable=subtechniqueVar)
    subtechniqueCombo.grid(row=17, column=2, columnspan=3, padx=10, pady=2, sticky='w')
    Label(mainframe, text="Sub-technique Description:", height=2).grid(row=18, column=1, sticky=W)
    subtechniqueDescriptionText = Text(mainframe, height=11, width=76, padx=2, pady=2, wrap=WORD)
    subtechniqueDescriptionScroll = Scrollbar(mainframe)
    subtechniqueDescriptionText.configure(yscrollcommand=subtechniqueDescriptionScroll.set, font=fontTuple, state='disabled')
    subtechniqueDescriptionText.grid(row=19, column=1, columnspan=4, rowspan=5)
    subtechniqueDescriptionScroll.config(command=subtechniqueDescriptionText.yview)
    subtechniqueDescriptionScroll.grid(row=19, column=5, columnspan=1, rowspan=5, sticky='ENS')
    subtechniqueVar.trace_add('write', subtechniqueSelected)

    Label(mainframe, text="CAPEC ID: ", height=2).grid(row=24, column=1)
    techniqueCapecIdText = Text(mainframe, height=1, width=50, padx=2, pady=2, wrap=WORD)
    techniqueCapecIdText.grid(row=24, column=2, columnspan=2, rowspan=1)
    techniqueCapecIdText.configure(font=fontTuple, fg= 'blue', cursor='trek', state='disabled')

    Label(mainframe, text="  ").grid(row=1, column=6)  # Filler column

    Label(mainframe, text="Technique/Sub-technique Data Components:", height=2).grid(row=1, column=7, sticky=W)
    dataComponentsListBox = Listbox(mainframe, height=11, width=88)
    dataComponentsScroll = Scrollbar(mainframe)
    dataComponentsListBox.configure(yscrollcommand=dataComponentsScroll.set, font=fontTuple)
    dataComponentsListBox.grid(row=2, column=7, columnspan=4, rowspan=8)
    dataComponentsScroll.config(command=dataComponentsListBox.yview)
    dataComponentsScroll.grid(row=2, column=11, columnspan=1, rowspan=8, sticky='ENS')
    dataComponentsListBox.bind('<<ListboxSelect>>', dataComponentSelected)

    Label(mainframe, text="Predicates realted to the selected Data Component:", height=2).grid(row=10, column=7, sticky=W)
    dcPredicateTreeView = ttk.Treeview(mainframe, column=(1, 2), show='headings')
    dcPredicateTreeView.column(1, anchor=CENTER, width=320)
    dcPredicateTreeView.column(2, anchor=CENTER, width=300)
    dcPredicateTreeView.heading(1, text='Data Component', anchor=CENTER)
    dcPredicateTreeView.heading(2, text='Predicate', anchor=CENTER)
    dcPredicateScroll = Scrollbar(mainframe)
    dcPredicateTreeView.configure(yscrollcommand=dcPredicateScroll.set)
    dcPredicateTreeView.grid(row=11, column=7, columnspan=4, rowspan=6)
    dcPredicateScroll.config(command=dcPredicateTreeView.yview)
    dcPredicateScroll.grid(row=11, column=11, columnspan=1, rowspan=6, sticky='ENS')
    dcPredicateTreeView.bind("<Double-1>", dcIrDoubleClicked)

    Label(mainframe, text="Interaction rule construction area:", height=2).grid(row=17, column=7, sticky=W)
    irConstructionText = Text(mainframe, height=13, width=88, padx=2, pady=2, wrap=WORD)
    irConstructionScroll = Scrollbar(mainframe)
    irConstructionText.configure(yscrollcommand=irConstructionScroll.set, font=fontTuple)
    irConstructionText.grid(row=18, column=7, columnspan=4, rowspan=6)
    irConstructionScroll.config(command=irConstructionText.yview)
    irConstructionScroll.grid(row=18, column=11, columnspan=1, rowspan=6, sticky='ENS')

    Label(mainframe, text="  ").grid(row=1, column=12)  # Filler column

    Label(mainframe, text="Attack entities (entities found in the TTP descriptions are highlighted):", height=2).\
        grid(row=1, column=13, sticky=W)
    entitiesListBox = Listbox(mainframe, height=8, width=85)
    entitiesScroll = Scrollbar(mainframe)
    entitiesListBox.configure(yscrollcommand=entitiesScroll.set, font=fontTuple)
    entitiesListBox.grid(row=2, column=13, columnspan=4, rowspan=5)
    entitiesScroll.config(command=entitiesListBox.yview)
    entitiesScroll.grid(row=2, column=17, columnspan=1, rowspan=5, sticky='ENS')
    entitiesListBox.bind('<<ListboxSelect>>', entitySelected)

    entitiesPredicatesListBox = Listbox(mainframe, height=4, width=85)
    entitiesPredicatesScroll = Scrollbar(mainframe)
    entitiesPredicatesListBox.configure(yscrollcommand=entitiesPredicatesScroll.set, font=fontTuple)
    entitiesPredicatesListBox.grid(row=8, column=13, columnspan=4, rowspan=3)
    entitiesPredicatesScroll.config(command=entitiesPredicatesListBox.yview)
    entitiesPredicatesScroll.grid(row=8, column=17, columnspan=1, rowspan=3, sticky='ENS')
    entitiesPredicatesListBox.bind("<Double-1>", entitiesPredicatesDoubleClicked)

    # Button(mainframe, text="Predicates from Description (LLM)", height=1, command=predicatesFromDescription).\
    #    grid(row=11, column=13, sticky=W)

    Button(mainframe, text="User as Attacker", height=1, command=userAsAttacker).grid(row=12, column=13, sticky=W)

    Label(mainframe, text="Permissions Required:", height=2).grid(row=13, column=13, sticky=W)
    permissionsRequiredText = Text(mainframe, height=1, width=70, padx=2, pady=2, wrap=WORD)
    permissionsRequiredText.grid(row=14, column=13, columnspan=3, sticky=W)
    permissionsRequiredText.configure(font=fontTuple, state='disabled')
    Button(mainframe, text="Add Predicate", height=1, command=handlePermissionsRequired).grid(row=14, column=15, sticky=W)

    Label(mainframe, text="System Requirements:", height=2).grid(row=15, column=13, sticky=W)
    systemRequirementsText = Text(mainframe, height=2, width=70, padx=2, pady=2, wrap=WORD)
    systemRequirementsText.grid(row=16, column=13, columnspan=3, sticky=W)
    systemRequirementsText.configure(font=fontTuple, state='disabled')
    # Button(mainframe, text="Add Predicate", height=1, command=handleSystemRequirements).grid(row=16, column=15, sticky=W)

    Label(mainframe, text="Platforms: ", height=2).grid(row=17, column=13, sticky=W)
    techniquePlatformsText = Text(mainframe, height=1, width=70, padx=2, pady=2, wrap=WORD)
    techniquePlatformsText.grid(row=18, column=13, columnspan=3, sticky=W)
    techniquePlatformsText.configure(font=fontTuple, state='disabled')
    Button(mainframe, text="Add Predicate", height=1, command=handlePlatforms).grid(row=18, column=15)

    Button(mainframe, text="Validate IR Syntax (LLM)", height=1, command=validateIrSyntax).grid(row=19, column=13, sticky=W)
    Label(mainframe, text="IR Syntax Validation Results:", height=2).grid(row=19, column=14, sticky=W)
    syntaxText = Text(mainframe, height=9, width=85, padx=2, pady=2, wrap=WORD)
    syntaxScroll = Scrollbar(mainframe)
    syntaxText.configure(yscrollcommand=syntaxScroll.set, font=fontTuple, state='disabled')
    syntaxText.grid(row=20, column=13, columnspan=4, rowspan=4)
    syntaxScroll.config(command=syntaxText.yview)
    syntaxScroll.grid(row=20, column=17, columnspan=1, rowspan=4, sticky='ENS')

    modelPath = r"C:\Users\dtayo\AppData\Local\nomic.ai\GPT4All\Meta-Llama-3.1-8B-Instruct-128k-Q4_0.gguf"
    llm = GPT4All(model=modelPath, temp=0.1, n_predict=500)
    syntaxValidationPrompt = "Answer the following questions: \
    Are the rule's parameters correct? \
    Are there any duplicate parameters? \
    Are there any parameters in the rule head that do not appear in the rule body? \
    Are there any parameters in the rule's body that do not appear in the rule's head? \
    Is the rule recursive?"

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
    techniqueFilter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
        Filter('kill_chain_phases.phase_name', '=', tacticShortName),
        Filter('x_mitre_is_subtechnique', '=', False)
    ]
    techniques = attackStix.query(techniqueFilter)
    for technique in techniques:
        techniquesList.append(technique['external_references'][0]['external_id'] + ' ' + technique['name'])

    techniquesList.sort()
    return techniquesList

def getTechniqueDetails(attackStix, techniqueId):
    techniqueFilter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', techniqueId)
    ]
    technique = attackStix.query(techniqueFilter)
    permissionsRequired = technique[0].get('x_mitre_permissions_required')
    permissionsRequired = '' if permissionsRequired is None else technique[0]['x_mitre_permissions_required']
    systemRequirements = technique[0].get('x_mitre_system_requirements')
    systemRequirements = '' if systemRequirements is None else technique[0]['x_mitre_system_requirements']
    return technique[0]['description'], permissionsRequired, systemRequirements, technique[0]['x_mitre_platforms']

def buildSubtechniqueList(attackStix, techniqueId):
    subtechniquesList = []
    subtechniqueFilter = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', 'contains', techniqueId),
        Filter('x_mitre_is_subtechnique', '=', True)
    ]
    subtechniques = attackStix.query(subtechniqueFilter)
    for subtechnique in subtechniques:
        subtechniquesList.append(subtechnique['external_references'][0]['external_id'] + ' ' + subtechnique['name'])

    subtechniquesList.sort()
    return subtechniquesList


# Find CAPEC-ID related to a Technique
def findCapecIdAndUrl(attackStix, techniqueId):
    capecID = ''
    capecURL = ''
    # Retrieve the Technique
    techniqueFilter = [
        Filter('type', '=', 'attack-pattern'),
        #Filter('name', '=', techniqueName)
        Filter('external_references.external_id', '=', techniqueId)
    ]
    technique = attackStix.query(techniqueFilter)
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

def searchListById(theList, Id):
    for elem in theList:
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
def updateDataComponents(techniqueID, relationshipsDF, predicatesDF, dcListBox):
    dataComponents = []
    for i in relationshipsDF.index:
        if relationshipsDF["technique_id"][i] == techniqueID and str(relationshipsDF["source_data_element"][i]) != 'nan':
            dataComponents.append(relationshipsDF["source_data_element"][i] + ' ' + relationshipsDF["relationship"][i] +\
                ' ' + relationshipsDF["target_data_element"][i])
    for i in range(len(dataComponents)):
        dcListBox.insert(i, dataComponents[i])
        # Highlight data components that have predicates
        for j in predicatesDF.index:
            if not pandas.isna(predicatesDF["DataComponent"][j]) and predicatesDF["DataComponent"][j].startswith(dataComponents[i]):
                dcListBox.itemconfig(i, bg=DC_HIGHLIGHT)

def updateDcInteractionRules(dataComponent, predicatesDF, dcIrTreeView):
    for i in predicatesDF.index:
        if not pandas.isna(predicatesDF["DataComponent"][i]) and predicatesDF["DataComponent"][i].startswith(dataComponent):
            lineTag = 'line'+str(len(dcIrTreeView.get_children()) % 2)
            dcIrTreeView.insert('', 'end', text="1", values=(predicatesDF["DataComponent"][i], predicatesDF["Predicate"][i]), tag=lineTag)
    dcIrTreeView.tag_configure('line0', background='gray')  # This highlights each second line, but the highlight is not visible in every monitor

# Build list of entities (and their synonyms)
# Highlight entities that appear in the description of selected Tactic/Technique/Sub-technique
def updateEntities(predicatesDF, entitiesDF, entitiesListBox, entitiesInTactic, entitiesInTechnique, entitiesInSubtechnique):
    entities = []
    for i in entitiesDF.index:
        entities.append(entitiesDF["Entity"][i])
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

# Build list of interaction rules for the selected question
def updatePredicates(selectedEntity, predicatesDF, entitiesPredicatesListBox):
    entityPredicates = []
    for i in predicatesDF.index:
        if predicatesDF["Entity"][i] == selectedEntity and str(predicatesDF["Predicate"][i]) != ''\
                and predicatesDF["Predicate"][i] not in entityPredicates:
            entityPredicates.append(predicatesDF["Predicate"][i])
    for i in range(len(entityPredicates)):
        entitiesPredicatesListBox.insert(i, entityPredicates[i])

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

# Predicates may be related to more than one data component.
# In this case, all the data components will be in DataComponent column, divided by ||.
# This method will duplicate such lines, each line with a different data component.
def duplicatePredicatesWithMultiDC(predicatesDF):
    for i in predicatesDF.index:
        if not pandas.isna(predicatesDF["DataComponent"][i]) and '||' in predicatesDF["DataComponent"][i]:
            dcs = predicatesDF["DataComponent"][i]
            rowsToAdd = dcs.count('||')
            # Add rows with the same values as the current row
            newRow = predicatesDF.iloc[i]
            for j in range(rowsToAdd):
                predicatesDF = pandas.DataFrame(numpy.insert(predicatesDF.values, i, newRow, axis=0), columns=predicatesDF.columns)
            # Update value of data component column of the new rows with each dc
            nextRow = i
            for dc in dcs.split('||'):
                predicatesDF.at[nextRow, "DataComponent"] = dc
                nextRow += 1

    return predicatesDF


if __name__ == '__main__':
    # enterprise-attack.json can be found at: https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack
    # We will use this data structure also to find connections between Techniques and CAPEC
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json").json()
    attackStix = MemoryStore(stix_data=stix_json["objects"])
    #printTacticTechniqueFromStix(attackStix)

    # Read relationships, which include Data Components, from CSV to DataFrame
    # Source of "techniques_to_relationships_mapping.csv":https://github.com/mitre-attack/attack-datasources/tree/main/docs
    relationshipsFilePath = "file:techniques_to_relationships_mapping.csv"  # Read from local path
    # Reading directly from github (the following line) doesn't work (read_csv throws exception)
    #relationshipsFilePath = "https://raw.githubusercontent.com/mitre-attack/attack-datasources/main/docs/techniques_to_relationships_mapping.csv"
    relationshipsDF = pandas.read_csv(relationshipsFilePath, keep_default_na=False)
    # Read mapping between predicates, questions and data components
    predicatesQuestionsAndDataComponentsDF = pandas.read_csv("file:QuestionsAndDataComponents.csv")
    predicatesQuestionsAndDataComponentsDF = duplicatePredicatesWithMultiDC(predicatesQuestionsAndDataComponentsDF)
    # Read list of attack ontology entities and their synonyms
    entitiesDF = pandas.read_csv("file:EntitiesAndSynonyms.csv", keep_default_na=False)
    displayTTP(attackStix, relationshipsDF, predicatesQuestionsAndDataComponentsDF, entitiesDF)
