# Developer Ethics

Kanidm is a project that will store, process and present people's personal data. This means we have a responsibility to
respect the data of all people who could be using our system - many who interact indirectly or do not have a choice in
this platform.

## Rights of people

All people using this software should expect to have the right to:

- Self control over their data, including the ability to alter or delete at any time.
- Free from harmful discrimination of any kind
- Informed consent over control and privacy of their data, including access and understand data held and shared on their
  behalf
- To be able to use and access this software regardless of ability, culture or language.

## Examples of situations for consideration

### Ability to be forgotten

#### Deletion is delete not flagging

When an account is deleted it must be truly deleted, not just flagged for future delete. Note that some functionality
like the recycle bin, we must keep the account details, but a recycle bin purge does truly delete the account.

### Self determination and autonomy

#### Self name change

People should be able to change their own name at anytime. Consider divorce, leaving abusive partners or other personal
decisions around why a name change is relevant.

This is why names are self-service writeable at any time.

### Free from harmful discrimination of any kind

#### Cultural and Social awareness of name formats

All name fields should be case sensitive utf8 with no max or min length limit. This is because names can take many forms
such as.

- firstname middlename lastname
- firstname lastname
- firstname firstname lastname
- firstname lastname lastname
- firstname
- middlename lastname
- lastname firstname

And many many more that are not listed here. This is why our names are displayName as a freetext UTF8 field, with case
sensitivity and no limits.

### Informed consent and Privacy of their data

#### Access to legalName field

legalName should only be on a "need to know" basis, and only collected if required. This is to help people who may be
stalked or harassed, or otherwise conscious of their privacy.

### To use and access this software regardless of ability

## Questions?

Please raise an issue with the project - we want to know if we have missed anything or can improve what we are doing.
