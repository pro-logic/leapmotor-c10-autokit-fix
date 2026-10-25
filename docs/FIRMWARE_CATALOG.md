# CPC200-CCPA / A15W firmware candidates

Checked **25 October 2026, Australia/Sydney**. This is a research catalogue,
not added patcher support. The builder still accepts only its exact original
`2025.10.15.1127` inputs. No dongle was updated during this search.

## Findings and evidence levels

The upstream maintainer's
[version comparison](https://github.com/lvalen91/CPC200-CCPA_resources/blob/main/documentation/01_Firmware_Architecture/version_comparison.md)
documents nine A15W builds, citing an offline archive for the older binaries.
Only the two 2025 images were independently inspected here. The older table
entries are leads; a corresponding downloadable original was not verified.

| Firmware version | Evidence found | Public original located here? |
| --- | --- | --- |
| `2022.04.25.1317` | Upstream analysis table | Not verified |
| `2022.11.19.1218` | Upstream analysis table | Not verified |
| `2023.05.29.1924` | Upstream analysis table | Not verified |
| `2023.09.27.1710` | Upstream analysis table | Not verified |
| `2024.01.19.1541` | Upstream analysis table | Not verified |
| `2024.08.07.2014` | Upstream analysis table | Not verified |
| `2024.09.03.1028` | Upstream analysis table | Not verified |
| `2025.02.25.1521` | Image inspected; embedded A15W model/version confirmed | [Yes](https://github.com/lvalen91/CPC200-CCPA_resources/blob/main/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img) |
| `2025.10.15.1127` | Image inspected; current supported baseline | [Yes](https://github.com/lvalen91/CPC200-CCPA_resources/blob/main/carlinkit/firmware_stock/A15W_Update_2025.10.15.1127.img) |
| `2026.07.31.1733` | First-hand provisioning log; not an inspected image | Not located |

The 2026 build appears in a user's
[LIVI issue report](https://github.com/f-io/LIVI/issues/366), in a stock A15W
backup directory name. That log identifies the hardware as `imx6ul_iw416`.
This establishes a useful lead, not an independently verified firmware image,
a latest-version claim, or compatibility with the development dongle.

Another first-hand
[discussion](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/discussions/218)
mentions `2024.01.11` and a vendor-provided image used to trigger hidden AutoKit.
The full build identifier and image contents were not verified here, so it is
not counted as another confirmed full version in the table.

## Genuine February image and current baseline

The files already present in the research collection were decrypted and read
in memory using this project's archive reader. Their embedded
`/etc/software_version` and `/etc/box_product_type` confirm the labels below.
Public GitHub file metadata also matches their locally computed Git blob IDs.
No firmware executable was run, and no vendor binary was added to this repo.

| Field | February candidate | Current baseline |
| --- | --- | --- |
| Embedded version | `2025.02.25.1521` | `2025.10.15.1127` |
| Embedded model | `A15W` | `A15W` |
| Image bytes | 12585685 | 11342661 |
| Image SHA-256 | `5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8` | `24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e` |
| Packed ARMadb-driver bytes | 211424 | 216520 |
| Packed driver SHA-256 | `baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd` | `614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb` |
| ARMAndroidAuto bytes | 575620 | 489800 |

The driver, AA executable and both startup scripts differ between these images.
February is a concrete next candidate for a deliberate port because its original
image is available. It still requires an exact unpacked driver, fresh hook/ABI
analysis and validation; it cannot be supported by changing the image hash alone.
See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

## Mislabelled download found

The [Ludwig archive index](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/blob/master/Firmware/A15W/README.md)
labels a link as February 2025. However, on the check date its
[image inside the February folder](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/blob/master/Firmware/A15W/_/2025.02.25.1521/A15W_Update.img)
actually contained **October 2025**:

- 11342661 bytes;
- embedded version `2025.10.15.1127`, model `A15W`;
- SHA-256 `24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e`;
- Git blob ID `b2991ef8058c60716b59145c2679fe584497d6ac`.

The actual public file was downloaded into memory, decrypted and checked,
confirming the metadata comparison. Do not count this path as a separate
February image. Use the verified lvalen91 link above for that candidate, and
always check embedded identity and hashes rather than trusting a folder name.

## Scope for further searches

Keep A15W separate from U2W, U2AW, U2AC and the unrelated RISC-V C2Air platform.
The upstream archive has separate model folders. AutoKit APK versions and
individual module build strings are also not stock dongle release identifiers.
Hardware/WiFi variants can differ even within A15W.

The upstream
[update architecture notes](https://github.com/lvalen91/CPC200-CCPA_resources/blob/main/documentation/04_Implementation/firmware_update.md)
describe a host-mediated vendor update API with device/batch parameters and a
token for downloads. This search did not submit the user's UUID, manufacturing
date or other device identifiers to that API. No exhaustive release list or
newest compatible version is claimed.
