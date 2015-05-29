# STARTTLS Everywhere - Installation

## Installation and configuration

```
$ git clone https://github.com/EFForg/starttls-everywhere.git
$ cd starttls-everywhere
$ pip install -r requirements.txt
$ mkdir /etc/starttls-everywhere
$ cp distrib/starttls-everywhere.cfg /etc/starttls-everywhere/
```

Now, edit the STARTTLS-Everywhere configuration file (/etc/starttls-everywhere/starttls-everywhere.cfg), then ensure the **data_dir** directory exists, otherwise create it:

```
$ mkdir /var/lib/starttls-everywhere
```

## MTA configuration tuning

Now, the **MTAConfigGenerator.py** program can be used to check the MTA general configuration:

```
$ sudo ./MTAConfigGenerator.py distrib/example_policy.json -m Postfix --fix
```

More details can be found on the [USAGE.md](USAGE.md) file.

## Load policies into MTA configuration

Once a policy definitions file has been downloaded and verified it can be loaded into MTA configuration:

```
$ sudo ./MTAConfigGenerator.py policy.json -m Postfix
[...]
Policy definitions NOT updated: use -s | --save to save them.
```

More details can be found on the [USAGE.md](USAGE.md) file.
