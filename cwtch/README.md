# Cwtch: Privacy Preserving Infrastructure for Asynchronous, Decentralized and Metadata Resistant Applications
Communications metadata is known to be exploited by various adversaries to undermine the security of systems, to track victims and to conduct large scale social network analysis to feed mass surveillance. Metadata resistant tools are in their infancy and research into the construction and user experience of such tools is lacking.

We present Cwtch, and extension of the metadata resistant protocol [Ricochet](https://ricochet.im) to support asynchronous, multi-peer group communications through the use of discardable, untrusted, anonymous infrastructure.

It is important to identify and understand that metadata is ubiquitous in communication protocols, it is indeed necessary for such protocols to function efficiently and at scale. However, information that is useful to facilitating peers and servers, is also highly relevant to adversaries wishing to exploit such information.

For our problem definition, we will assume that the content of a communication is encrypted in such a way that an adversary is practically unable break, as such we will limit our scope to the context of a communication (i.e. the metadata).

We seek to protect the following communication contexts:


* **Who** is involved in a communication? It may be possible to identify people or simply device or network identifiers. (e.g. This communication involves Alice and Bob.)
* **Where** are the participants of the conversation?  (e.g. During this communication Alice was in France and Bob was in Canada.)
* **When** a conversation takes place? The timing and length of communication can reveal plenty about the nature of a call. (Alice and Bob talked for 23 minutes and 43 seconds yesterday evening at 6pm.)
* **How** was the conversation mediated? Whether a conversation took place over email or a telephone call can provide useful intelligence. (Alice and Bob spoke on the phone yesterday.)
* **What** is the conversation about? - Even if the content of the communication is encrypted it is sometimes possible to derive a probable context of a conversation without knowing exactly what is said (e.g. a person calling a pizza store at dinner time,or someone calling a known suicide hotline number at 3am.)

Beyond individual conversations, we also seek to defend against context correlation attacks, whereby multiple conversations are analyzed to derive higher level information:

* **Relationships** - Discovering social relationships between parties by analyzing the frequency and length of their communications over a period of time. (Carol and Eve call each other every single day for multiple hours at a time.)
* **Cliques** - Discovering social relationships between multiple parties by deriving casual communication chains from their communication metadata (e.g. everytime Alice talks to Bob she talks to Carol almost immediately after.)
* **Pattern of Life** - Discovering which communications are cyclical and predictable. (e.g. Alice calls Eve every Monday evening for around an hour.)


More Information: [https://cwtch.im](https://cwtch.im)

Development and Contributing information in [CONTRIBUTING.md](https://git.openprivacy.ca/cwtch.im/cwtch/src/master/CONTRIBUTING.md)

## Running Cwtch
### Server
#### Docker

### NOTE: The following section is out of date. The new Cwtch server is available from https://git.openprivacy.ca/cwtch.im/server, but there is no current docker container for it.

This repository contains a `Dockerfile` allowing you to build and run the server as a [docker](https://www.docker.com/) container.

To get started issue `docker build -t openpriv/cwtch-server:latest .`, this will create 2 temporary docker containers, one to build the Tor daemon and one to build Cwtch. The compiled binaries will then be bundled into a new image and tagged as `openpriv/cwtch-server:latest`.

To run Cwtch in the foreground execute `docker run openpriv/cwtch-server:latest`, you will see a small amount of output from Tor and then Cwtch will output your server address. When you `Ctrl + C` the container will terminate. To run Cwtch in the background execute `docker run --name my-cwtch-server -d openpriv/cwtch-server:latest`. To get your Cwtch server address issue `docker logs my-cwtch-server`.

The image creates 3 volumes, for /etc/cwtch, /etc/tor, /var/lib/tor

##### Upgrading

To upgrade with continuity

```
# Stop current container/service
docker stop my-cwtch-server

docker pull openpriv/cwtch-server

# Create a new container and copy the volumes (cwtch/onion keys, message store)
docker create --name my-cwtch-server-2 --volumes-from my-cwtch-server openpriv/cwtch-server:latest

# Resume service with the new container
docker start my-cwtch-server-2
```

![](https://git.openprivacy.ca/avatars/5?s=140)
