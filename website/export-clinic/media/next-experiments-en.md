# Web and mobile: separate, explicitly scoped experiments

Status: planning only. The completed recording concerns Telegram Desktop and local export files.

| Environment | Next experiment | Claim that would be supported |
| --- | --- | --- |
| Telegram Web | Use an owned test account and a clearly labeled browser session. Show a test message, deliberately change its local presentation with visible developer controls, compare with an unmodified session, and check what happens after reload. | A browser can display locally changed content while the page address still refers to the legitimate service. This would not demonstrate a Telegram server change. |
| Official Android client | Show the same test conversation in the official app on an identified device, compare it with the changed Desktop export, and separately record an ordinary edit/deletion of owned test messages. | A cross-client comparison and the current state visible to that account. This would not establish modification of Android's protected application storage. |
| Official iOS client | Repeat the comparison on an identified iPhone and official app version. Keep any experimental custom build explicitly identified as such. | The behavior actually observed on that device and version. A custom build would not be evidence about the unchanged App Store binary. |

Telegram lists its official Web, Android and iOS clients on its [applications page](https://telegram.org/apps). Its [documented HTML/JSON export workflow](https://telegram.org/blog/export-and-more) uses Telegram Desktop. The completed Desktop experiment should not be described as a mobile or Web export test.

The Web experiment can use ordinary, visible browser editing controls. [Chrome's DOM documentation](https://developer.chrome.com/docs/devtools/dom/) describes inspecting and changing a page locally. The record must identify that intervention and retain an unmodified comparison session.

Any later mobile-storage experiment needs a separate feasibility check for the exact device, OS, app version, access level, backup coverage and behavior after synchronization. Android backup coverage is configurable and varies with platform and transfer mode; a generic backup mechanism is not evidence that arbitrary Telegram cache replacement works. [Android Auto Backup](https://developer.android.com/identity/data/autobackup)

Do not state that ordinary retail devices can always accept a modified Telegram database through backup restore, that all forensic tools would accept it, or that such changes are undetectable. Those are separate empirical claims requiring their own evidence.

For each new recording, retain the original capture, describe every intervention, identify what was observed, and distinguish it from conclusions that remain untested.
