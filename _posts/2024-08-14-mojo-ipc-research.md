---
layout: post
title:  "Mojo IPC Research"
date:   2024-08-14 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Mojo stands for Chromium's IPC subsystem. \
This page contains general findings regarding Mojo. 

Conducted on Chrome-127.

## `Connector`

Part of the bindings layer, performs R/W operations on a `MessagePipe`. Multiple associated interfaces may be defined on the same underlying pipe, while each connector uniquely belongs to a single primary interface. \
This member is set within `Connector::Connector`, hence - exists in memory only for already-bounded interfaces. 

We may fetch the corresponding interface name by reading `Connector::interface_name_`. This member is used commercially within the handle watcher initialization, whenever `Connector::WaitToReadMore` is called. Moreover, it is also used for tracing within `Connector::DispatchMessage`:

```cpp
  // This emits just full class name, and is inferior to full mojo tracing, so
  // the category is "toplevel" if full tracing isn't available. If it's
  // available, it's emitted under "disabled-by-default-mojom" for debugging
  // purposes.
  // TODO(altimin): This event is temporarily kept as a debug fallback. Remove
  // it once the new implementation proves to be stable.
  TRACE_EVENT(
      TRACE_DISABLED_BY_DEFAULT("mojom"), "Connector::DispatchMessage",
      [&](perfetto::EventContext& ctx) {
        ctx.event()->set_chrome_mojo_event_info()->set_mojo_interface_tag(
            interface_name_);

        static const uint8_t* flow_enabled =
            TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED("toplevel.flow");
        if (!*flow_enabled)
          return;

        perfetto::Flow::Global(message.GetTraceId())(ctx);
      });
```

As we can see, we can use `chrome://tracing` to record traces. For mojo, we should enable `toplevel.flow` and `ipc.flow` tracing categories. \ 
Can learn more about the tracing mechanism [here][chrome-tracing]


## Google - Automated IPC Fuzzing

The following [commit][fuzzing-commit] adds a basic automated way to fetch the desired interfaces for fuzzing, as well as their corresponding `.mojom`s. The relevant entry point resides within `ipc_interfaces_dumper.cc`. \ 
It distinguishes between 3 types of *bound* interfaces: regular-embedders, associated-embedders, and process.

```cpp
  content::RenderFrameHost* rfh = browser()
                                      ->tab_strip_model()
                                      ->GetActiveWebContents()
                                      ->GetPrimaryMainFrame();

  std::vector<std::string> rfh_interfaces;
  std::vector<std::string> rfh_interfaces_associated;
  std::vector<std::string> process_interfaces;

  content::GetBoundInterfacesForTesting(rfh, rfh_interfaces);
  content::GetBoundAssociatedInterfacesForTesting(rfh,
                                                  rfh_interfaces_associated);
  content::GetBoundInterfacesForTesting(rfh->GetProcess(), process_interfaces);
```

Internally, the embedders-interfaces methods are calling `RenderFrameHostImpl::GetBoundInterfacesForTesting`, which under the hood just parses the broker's binders map, calling `GetInterfacesForTesting` for both `binder_map_` and `binder_map_with_context_`:

```cpp
void GetBinderMapInterfacesForTesting(std::vector<std::string>& out) {
    binder_map_.GetInterfacesForTesting(out);
    binder_map_with_context_.GetInterfacesForTesting(out);
  }
```

 This means that nothing too fancy is going on here. \
For the process interfaces, an async task is being posted, calling `RenderProcessHostImpl::IOThreadHostImpl::GetInterfacesForTesting`. This method simply parses the `service_manager::BinderRegistry* binders_` member of the `RenderProcessHostImpl` object:

```cpp
void RenderProcessHostImpl::IOThreadHostImpl::GetInterfacesForTesting(
    std::vector<std::string>& out) {
  binders_->GetInterfacesForTesting(out);  // IN-TEST
}
```

This seems to be a major drawback with this solution - it only scans interfaces registered to the binder maps or the `binders_` member of the process. In case an interface wasn't registered in such ways (for example, in case it was registered via `Supplement`) - it won't be detected. \
Moreover, all of the above only applies for already-bound interfaces. 

If we only care about bound interfaces, a better methodic approach would be scanning the whole memory of the Renderer, finding for occurences of the `Connector` class, and reading its `interface_name_` member. \
Of course, this idea has its own drawback - that only initialized interfaces are considered. \
We have to figure out a more systemathic approach. Keep in mind that `BrowserInterfaceBroker` might be useful here. 



[chrome-tracing]: https://www.chromium.org/developers/how-tos/trace-event-profiling-tool/
[fuzzing-commit]: https://github.com/chromium/chromium/commit/90ef9055a5bdfca5e9bf7b95cbb224d56ed6e056
