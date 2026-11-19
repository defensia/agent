
Ú
@f8759a75c04f952184fda794ce16975b1cc32f99cfd814f2bfb07d62e2fb9c29@9ce9a5a21c0494ad5c26a783235203527dd95f4c748d4902754d49c71eebe1a1
coredns"s
Gsha256:268d098da3b0dce6ca6d71044c55aeed2cde53d7440e5987ab48ecfc1c209125í'rancher/mirrored-coredns-coredns:1.14.3*Gsha256:268d098da3b0dce6ca6d71044c55aeed2cde53d7440e5987ab48ecfc1c20912508˙“π•é›‚ÙB1
io.kubernetes.pod.namecoredns-8db54c48d-dr94kB*
io.kubernetes.pod.namespacekube-systemB=
io.kubernetes.pod.uid$94461ec8-09d0-4173-89b5-25866953ea29B'
io.kubernetes.container.namecorednsJ(
io.kubernetes.container.hashaa732e91J)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30J∆
io.kubernetes.container.ports§[{"name":"dns","containerPort":53,"protocol":"UDP"},{"name":"dns-tcp","containerPort":53,"protocol":"TCP"},{"name":"metrics","containerPort":9153,"protocol":"TCP"}]
ö
@c3981095f1919aab690dd934af7d5e55446207a687e22a76be028cf225301976@885f783fff61bd75d520312439d5b813883934d805dbbd3d5ae774ed80445e76
metrics-server"r
Gsha256:b39bceeb0c5918ba1b41c8c9eaf39801280f82909548a1e2cae089f8af6094e7í&rancher/mirrored-metrics-server:v0.8.1*Gsha256:b39bceeb0c5918ba1b41c8c9eaf39801280f82909548a1e2cae089f8af6094e708˚¥Œ†é›‚ÙB*
io.kubernetes.pod.namespacekube-systemB=
io.kubernetes.pod.uid$0b62a7e1-80b7-4793-b6f7-bdea3a99b1d1B.
io.kubernetes.container.namemetrics-serverB9
io.kubernetes.pod.namemetrics-server-786d997795-lhllzJ(
io.kubernetes.container.hash6c58972cJ)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30JZ
io.kubernetes.container.ports9[{"name":"https","containerPort":10250,"protocol":"TCP"}]
∞
@cb63a1ecf06a21ecb53c68200aade23156ff1b2a74e79faf50e9337292ada8da@86b3f1fa931ec77e4d68944a6b21cfdc2eab1f0ee349ef2a82f0fc7f68efb125
traefik"s
Gsha256:f6812724be8993ef6b8935543d68c5305fba26ddd800c141752d152d8005538cí'rancher/mirrored-library-traefik:3.6.13*Gsha256:f6812724be8993ef6b8935543d68c5305fba26ddd800c141752d152d8005538c08ôÜΩ°é›‚ÙB'
io.kubernetes.container.nametraefikB0
io.kubernetes.pod.nametraefik-9bcdbbd9-t5cz7B*
io.kubernetes.pod.namespacekube-systemB=
io.kubernetes.pod.uid$f2eee9f2-89f8-4232-ad14-cbecb15aa859J(
io.kubernetes.container.hashcc55fe1bJ)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod60JÖ
io.kubernetes.container.ports„[{"name":"metrics","containerPort":9100,"protocol":"TCP"},{"name":"traefik","containerPort":8080,"protocol":"TCP"},{"name":"web","containerPort":8000,"protocol":"TCP"},{"name":"websecure","containerPort":8443,"protocol":"TCP"}]
÷
@c859740978a6b922bcdaa89a4d295b1c99f7773bc28cff4ecf05082c94d3fc4d@422fb3d86d13143dfd3ffdfbd85ffd4d4e55d25b26069807bee45a020054415c
nginx"]
Gsha256:96868d9fa38f469a86d2f25787e43ee9ad330339d30be260aa9f5a338bb03751ínginx:1.27-alpine*Gsha256:96868d9fa38f469a86d2f25787e43ee9ad330339d30be260aa9f5a338bb0375108∂òæ ¿„ÙB%
io.kubernetes.container.namenginxB$
io.kubernetes.pod.name
shop-nginxB&
io.kubernetes.pod.namespaceclienteB=
io.kubernetes.pod.uid$a32c61b3-0b52-4008-99bc-1b22232e8c60JX
io.kubernetes.container.ports7[{"hostPort":8081,"containerPort":80,"protocol":"TCP"}]J(
io.kubernetes.container.hash5fafb28fJ)
$io.kubernetes.container.restartCount0JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30
ï
@93f56a405838ccb4c1c920a08b9e1b5f56ac44cd5dc8eeabd2d6fbbe5aea5bdc@2dc4e60922b41cef7ceabd9372b5e774da01cefe4ce3bcb555ad96cf69f4d2b7

lb-tcp-443"f
Gsha256:1084dac5ea9871ffa6d01fe67150e175df9c28579073cd40d2186c08b37aba50írancher/klipper-lb:v0.4.17*Gsha256:1084dac5ea9871ffa6d01fe67150e175df9c28579073cd40d2186c08b37aba5008ñ–â™å›‚ÙB*
io.kubernetes.pod.namespacekube-systemB=
io.kubernetes.pod.uid$1a754a55-ab58-4eee-a039-8dd2dfc3392eB*
io.kubernetes.container.name
lb-tcp-443B6
io.kubernetes.pod.namesvclb-traefik-613753bb-fkrnlJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30Jl
io.kubernetes.container.portsK[{"name":"lb-tcp-443","hostPort":443,"containerPort":443,"protocol":"TCP"}]J(
io.kubernetes.container.hash93cfbcd9J)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-log
˛
@5a07c0cf0b8ef0a8e4c9ecf2cf92c504167d8e05b57c97f6fb9dc518afb8a143@170c1f060bac50f3bba18b81ac836928e962f44958656c3c9ff4d5a216485113
nginx"_
Gsha256:92873713839a611eb0c8d4dccba8890794ead292de24c16c4a4883f35639d8e1ínginx:1.26-bookworm*Gsha256:92873713839a611eb0c8d4dccba8890794ead292de24c16c4a4883f35639d8e108∞æË‘À„ÙB&
io.kubernetes.pod.namespaceclienteB=
io.kubernetes.pod.uid$921bd5a7-4684-4bf6-942b-6fb9b9e64e01B%
io.kubernetes.container.namenginxB$
io.kubernetes.pod.name
api-debianJ)
$io.kubernetes.container.restartCount0JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30J(
io.kubernetes.container.hashcee18242
ê
@5e0b6400034fd23c41df85312578d304050104f98e81e167477b6d5559696f6f@2dc4e60922b41cef7ceabd9372b5e774da01cefe4ce3bcb555ad96cf69f4d2b7
	lb-tcp-80"f
Gsha256:1084dac5ea9871ffa6d01fe67150e175df9c28579073cd40d2186c08b37aba50írancher/klipper-lb:v0.4.17*Gsha256:1084dac5ea9871ffa6d01fe67150e175df9c28579073cd40d2186c08b37aba5008‡˜ﬂ‹ã›‚ÙB=
io.kubernetes.pod.uid$1a754a55-ab58-4eee-a039-8dd2dfc3392eB)
io.kubernetes.container.name	lb-tcp-80B6
io.kubernetes.pod.namesvclb-traefik-613753bb-fkrnlB*
io.kubernetes.pod.namespacekube-systemJ(
io.kubernetes.container.hash5e234596J)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30Ji
io.kubernetes.container.portsH[{"name":"lb-tcp-80","hostPort":80,"containerPort":80,"protocol":"TCP"}]
Ø
@05faed750099a17e17964ff91dc2b42c09ec62f7273a6a7bce8b3f2bca0bd060@ed2ef50886108ed3473d36bfa7c4e42eb096436ce344efbdc77654b47c1d6f23
defensia-agent"j
Gsha256:e4e9adf33be2bc3cc5dd841ffc8ba649c99664dfd0e6b05e7fe92449c628698díghcr.io/defensia/agent:1.4.107*Gsha256:e4e9adf33be2bc3cc5dd841ffc8ba649c99664dfd0e6b05e7fe92449c628698d08ôÇ‰Ÿé›‚ÙB&
io.kubernetes.pod.namespaceclienteB=
io.kubernetes.pod.uid$ecd1e972-8364-4563-b3e5-22725ae52621B.
io.kubernetes.container.namedefensia-agentB6
io.kubernetes.pod.namecliente-defensia-agent-kbnqdJ.
(io.kubernetes.pod.terminationGracePeriod30J(
io.kubernetes.container.hashfd17586dJ)
$io.kubernetes.container.restartCount1JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFile
‘
@732c9cb75398b84cc0d0bdef1a52a9eaeadbc69a1d24544a35efec06934b20ac@a3befb0a71f440e73e55d4766ccb89784bf7c104c5ab2021283d4a457f3b1d8d
local-path-provisioner"r
Gsha256:58d078c5467bf37b5bf5230f2a85dcfe40fc7042062ab8823757ec7822aaeb22í&rancher/local-path-provisioner:v0.0.36*Gsha256:58d078c5467bf37b5bf5230f2a85dcfe40fc7042062ab8823757ec7822aaeb2208∏ÏﬂÆÆ›‚ÙB*
io.kubernetes.pod.namespacekube-systemB=
io.kubernetes.pod.uid$a129a141-45b8-4fa2-8be4-2f0e523a6543B6
io.kubernetes.container.namelocal-path-provisionerBA
io.kubernetes.pod.name'local-path-provisioner-5d9d9885bc-4f2lfJ)
$io.kubernetes.container.restartCount0JF
.io.kubernetes.container.terminationMessagePath/dev/termination-logJ8
0io.kubernetes.container.terminationMessagePolicyFileJ.
(io.kubernetes.pod.terminationGracePeriod30J(
io.kubernetes.container.hash6649ab14