### Changed

- **A refused clear-synced-copies suspend now has a drift guard on its message.** The refusal tells the person how to cut access right away ("suspend without clearing synced copies to cut access immediately"). The API, CLI, web and journey tests already carried that text; a new server test fails if the CLI or web test fixtures stop matching the text the server sends. No behaviour change.
