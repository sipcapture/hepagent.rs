<img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=120/>

# HEPagent

Next-Generation [HEP](https://github.com/sipcapture/hep) Capture Agent in Rust


#### Instructions
##### Requirements
* Install [rustup](https://rustup.rs)
* Install `libluajit` 
  * Debian: `apt install libluajit-5.1-dev`
  * CentOS: `yum install libluajit-5.1-devel`

#### Build
* Run `cargo build --release`

#### Docker Build
* Dynamic
  `docker build -t sipcapture/hepagent -f docker/Dockerfile .`
* Static _(work in progress)_
  `docker build -t sipcapture/hepagent-static -f docker/Dockerfile-static .`

---------

#### Developers
Contributors and Contributions to our project are always welcome! If you intend to participate and help us improve by sending patches, we kindly ask you to sign a standard [CLA (Contributor License Agreement)](http://cla.qxip.net) which enables us to distribute your code alongside the project without restrictions present or future. It doesn’t require you to assign to us any copyright you have, the ownership of which remains in full with you. Developers can coordinate with the existing team via the [homer-dev](http://groups.google.com/group/homer-dev) mailing list. If you'd like to join our internal team and volunteer to help with the project's many needs, feel free to contact us anytime!

##### Architecture
```
bpf -> pnet -> packets mod 
               - pre-parse a packet
               - if it's one of the types we want, TCP/UDP etc, pass it to lua capture plan
               -> capplan.lua
                  - run parsing logic
                  - call into rust module callbacks when need to do certain actions
                      -> sip rust module: parse, check method, parse out session params
                      -> hep rust module: send prepared HEP packet
                         -> calls into the publish module via mpsc channel
                      -> json rust module: send prepared json payload
                         -> should call into the json publish mpsc channel too
```

##### Modules
Rust modules register using `register_module` functions passing in Scripting instance - which allows to register in Lua.

For dynamic module loading those could be compiled as dynamic libs and `register_module` exported as #[no_mangle] symbol, making it an entry point for each module registration.

--------



#### License & Copyright

![H5](https://img.shields.io/badge/license-GNU_AGPL_v3-blue.svg)

Code released under the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

*(C) 2020 [QXIP BV](http://qxip.net)*

----------

#### Made by Humans
This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.<br>
If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest) 
