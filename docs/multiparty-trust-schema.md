# The Synatax of Multiparty Trust Schema

We use an example to explain the synatx:

```ascii
pkt-name /example/data/*
rule-id rule1
all-of
{
  "" 3x/example/a/KEY/*
  "" /example/b/KEY/*
}
at-least-num 2
at-least
{
  "" /example/c/KEY/*
  "" /example/d/KEY/*
  "" /example/e/KEY/*
}
```

## pkt-name

The packet name pattern that the schema rule applies to.
The value is a wildcard name.

> **wildcard name**: A NDN name with `*` that can match any single name component. 

In our example, the configuration file will apply to any packet whose name has three components and under the prefix of `/example/data`.

## rule-id

A unique ID of the rule.
For the same pkt-name, there can be multiple rules.
When there are multiple rules, a packet signaure is valid if it can pass any one rule.

## all-of

A list of wildcard name are listed under this field.
This means a packet's signature should contain signature pieces whose signers can match all the listed wildcard names.
In our example, the signature must contain three signers whose key name is of pattern `/example/a/KEY/*` and one signer whose key name can match `/example/b/key/*` AT THE SAME TIME.
Note that there is a quantifying prefix before the wildcard name.

> **quantifying prefix**: When a quantifying prefix nx appears, the wildcard name will match n different names instead of one name.

## at-least-num

The number indicates how many signers from the `at-least` can satisfy the requirement.

## at-least

A list of wildcard name are listed under this field.
This means a packet's signature should contain signature pieces whose signers can match `at-least-num` of the listed wildcard names.