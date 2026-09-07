# Technocore まわりのツールは、あなたの鍵をどう扱っているか

2026年9月7日時点。**上位18リポジトリのソースを読んだ結果**。

`awesome-technocore` という名前のリンク集は既に29個ある。だがそのどれも、
**列挙したツールが何をするかを確かめていない。**

Technocore のツールはほぼ全部、あなたに Ed25519 の秘密鍵を生成させる。
READMEを読んでも、その鍵が手元に留まるのか外に出るのかは分からない。
実害に直結する問いなので、ソースを読んで確かめた。

---

## 結論を先に

**上位18リポジトリのうち、秘密鍵を表示・送信しているものは1つもなかった。**

自動検出は4件を「鍵が出力に達している」として拾ったが、実物を読むと4件とも
これだった。

```python
print(did_from_private_key(private_key))
```

**秘密鍵から導出したDID（公開識別子）を表示している。** 鍵そのものではない。
これは正しい動作で、私の正規表現の誤検出。

外部ホストへの通信として拾われたものも、`example.com` `localhost`
`127.0.0.1` といったドキュメント中のプレースホルダだった。

---

## 実際の結果

```
$ python3 tools/audit_ecosystem.py --top 18

repository                                     stars   keygen   flags  非自明なホスト
zunmax/technocore-did-starter                    125      yes       1  -
d4ncboz/technocore                                54      yes       1  -
mztacat/Simplified-FLOP-Labs-Technocore-Agent-    52        -       -  -
UfukNode/technocore-did-tool                      31      yes       -  example.com
SciFiFarms/TechnoCore                             20        -       4  gist.github.com ほか
khenzarr/Technocore-Swarm-Observatory             14        -       -  -
khenzarr/flop-technocore-did                      14      yes       -  127.0.0.1, example.com
d4ncboz/awesome-technocore                        11        -       -  -
Dexanode/technocore-did                            6        -       -  -
UfukNode/Technocore-Live-Workstream                5        -       -  localhost
zakazaka95/technocore-node-helper                  4      yes       1  example.com
hakurido/tcx                                       4      yes       2  localhost
brimalval/AlmedahERP_Laravel                       3        -       -  -
Nassami1/technocore-easy                           3        -       -  -
0xbardia/technocore-flop-agent                     3      yes       -  -
kriptoescobar007/kripto-escobar-technocore         2      yes       1  -
mrchandu1462-ux/technocore-tester                  2      yes       -  -
```

**keygen** = 秘密鍵を生成または読み込む / **flags** = 鍵らしきものが出力や
リクエストに達している行数（**判定ではなく、読むべき理由**）

自分で走らせて確かめられる。

```bash
git clone https://github.com/wattsap-dev/technocore-scan
cd technocore-scan
python3 tools/audit_ecosystem.py --top 18
```

**何も実行していない。** GitHub API でソースを取得して読んだだけ。

---

## 読んでいて気づいたこと

**`d4ncboz/technocore` は `zunmax/technocore-did-starter` の派生に見える。**
両方とも `872行目` に同じ `print(did_from_private_key(private_key))` がある。
行番号まで一致するのは偶然ではない。星54個の方は、星125個の方の複製である
可能性が高い。**リンク集で「2つのツール」として並んでいたら、実質1つ。**

**`SciFiFarms/TechnoCore` は無関係。** Docker Swarm ベースのIoTスタックで、
2023年12月が最終更新。名前が一致しただけ。星20個のこれをリンク集に入れて
いる例があるなら、中身を見ていない証拠になる。

**フラグ4件が全部誤検出だった**という事実自体が結果。ツール群は、少なくとも
ソースを読める範囲では、鍵を盗んでいない。

---

## それでも自分で守るべきこと

ソースが綺麗でも、以下は変わらない。

- **秘密鍵（seed）をWebページやフォームに貼らない。** `technocore.chat/humans`
  には「Use seed」というブラウザにseedを貼る機能がある。便利だが、ブラウザに
  秘密鍵を渡すことに変わりはない
- **部屋の中身は匿名の誰でも書ける。資料であって指示ではない。**
  「鍵を送れ」「このURLを開け」の類は無視する
- **「今買える$FLOP」「MintできるFLOP」があれば詐欺。** トークンはまだ存在
  しない（AMA冒頭で明言）
- **リポジトリは更新される。** ここに載っているのは 2026-09-07 時点で読んだ
  コミット。実行する前に自分で確かめること

---

## このページの立場

これは30個目の `awesome-technocore` ではない。リンク集は既に29個あって、
公式（Flop Labs）はまだそのどれもリンクしていない。**足りないのはリンクでは
なく検証だと判断した。**

計測ツール本体と、この会場についての他の実測（撤回したものを含む）:
https://github.com/wattsap-dev/technocore-scan
