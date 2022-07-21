/*************************/
/ Predicates Declarations /
/*************************/
derived(accessFile(_Prin, _Server, _Access, _ServerPath)).
derived(localFileProtection(_Host, _User, _Access, _Path)).

meta(attackGoal(_)).

/*******************************************/
/****      Tabling Predicates          *****/
/* All derived predicates should be tabled */
/*******************************************/
:- table accessFile/4.
:- table localFileProtection/4.

/*******************/
/ Interaction Rules /
/*******************/
interaction_rule(
 (accessFile(Prin, Server, Access, ServerPath) :-
  nfsMounted(Client, ClientPath, Server, ServerPath, Access),
  accessFile(Prin, Client, Access, ClientPath)),
 rule_desc('principal Prin can access files on a NFS server if the files on the server are mounted at a client and he can access the files on the client side', 1.0)).

interaction_rule(
 (accessFile(Prin, Client, Access, ClientPath) :-
  nfsMounted(Client, ClientPath, Server, ServerPath, read),
  accessFile(Prin, Server, Access, ServerPath)),
 rule_desc('principal Prin can access files on a NFS client if the files on the server are mounted at the client and he can access the files on the server side', 1.0)).

interaction_rule(
 (localFileProtection(Host, User, Access, Path) :-
  fileOwner(Host, Path, User),
  ownerAccessible(Host, Access, Path)),
 rule_desc('The User on machine Host can have the specified Access to the file Path.', 1.0)).

interaction_rule(
 (localFileProtection(Host, User, Access, Path) :-
  inGroup(User, Group),
  fileGroupOwner(Host, Path, Group),
  groupAccessible(Host, Access, Path)),
 rule_desc('', 1.0)).

interaction_rule(
 (localFileProtection(Host, User, Access, Path) :-
  worldAccessible(Host, Access, Path)),
 rule_desc('', 1.0)).

interaction_rule(
 (accessFile(Principal, Host, Access, Path):-
  localFileProtection(Host, User, Access, Path),
  localAccess(Principal, Host, User)),
 rule_desc('Principal can access data at Path on Host with Access privilege.', 1.0)).

