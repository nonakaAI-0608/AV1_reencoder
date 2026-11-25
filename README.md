# AV1_reencoder（動画 再エンコード・安全置換ツール）

動画を ffmpeg で HEVC（libx265）または AV1（SVT-AV1）に再エンコードし、完了・検証後に元のファイルと安全に置き換える Windows 向け GUI ツールです。

## 必要なもの
- Windows 10 / 11
- Python 3.10 以降（python.org 版、Python Launcher を含める）
- [ffmpeg](https://ffmpeg.org/download.html)（libx265 / libsvtav1 を含むビルド。例：gyan.dev の full build）

## インストール
1. このリポジトリを ZIP でダウンロードして展開するか、`git clone` します。
2. （任意）依存ライブラリを入れます：`py -3 -m pip install -r requirements.txt`
   - tkinterdnd2：ドラッグ＆ドロップ
   - psutil：処理の優先度・負荷の制御
3. `AV1_reencoder_起動.bat` で起動し、画面上で `ffmpeg.exe` を指定して「動作確認」を押します。

## データの保存場所
作業状態は `%LOCALAPPDATA%\MP4_x265_Reencoder\` に保存されます。

## ライセンス
MIT License（[LICENSE](LICENSE)）。ffmpeg はそれぞれのライセンスに従います（同梱していません）。
