# raspbian-ca-update

古いRaspbianシステムのCA証明書を更新するツール

バージョン: 1.0.0

## 概要

古いRaspbianシステムでは、OpenSSLバージョンの依存関係により通常のパッケージ管理システムでCA証明書を更新できない場合があります。このツールは、最新のCA証明書を直接ダウンロードして更新することで、SSL/TLS接続の問題を解決します。

## 機能

- 最新のCA証明書をcurl.seから自動ダウンロード
- 既存の証明書の自動バックアップ
- 証明書ハッシュリンクの再構築
- SSL接続テスト機能
- 現在の証明書状態の確認

## インストール

```bash
go build -o raspbian-ca-update raspbian_ca_update.go
sudo cp raspbian-ca-update /usr/local/bin/
```

## 使用方法

### CA証明書の更新
```bash
sudo raspbian-ca-update
```

### 現在の証明書状態を確認
```bash
raspbian-ca-update --check
```

### ヘルプを表示
```bash
raspbian-ca-update --help
```

### Raspbian以外のシステムで強制実行
```bash
sudo raspbian-ca-update --force
```

### 証明書検証をスキップして更新（insecureモード）
```bash
sudo raspbian-ca-update --insecure
```

### オプションを組み合わせて使用
```bash
sudo raspbian-ca-update --force --insecure
```

## オプション

- `--help`, `-h`: ヘルプメッセージを表示
- `--version`, `-v`: バージョン情報を表示
- `--check`: 現在のCA証明書の状態を確認
- `--force`: Raspbian以外のシステムでも強制的に実行
- `--insecure`: ダウンロード時にSSL証明書の検証をスキップ（現在の証明書が古い場合に使用）

## 動作の流れ

1. 既存のCA証明書をバックアップ (`/etc/ssl/certs/ca-certificates.crt.backup`)
2. curl.seから最新のCA証明書をダウンロード
3. ファイル権限を設定 (644)
4. 証明書ハッシュリンクを再構築
5. SSL接続テストを実行

## 要件

- Go 1.24.4以降
- root権限（sudo）
- インターネット接続

## ライセンス

MIT License

Copyright (c) 2025 Ryu Tanabe (bellx2)

## 作者

Ryu Tanabe (bellx2)  
https://github.com/bellx2