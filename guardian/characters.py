"""マスコットのキャラクターと吹き出しのセリフ。設定は docs/キャラクター設定.md を参照。"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_CHARACTER = "luce"


@dataclass(frozen=True)
class Character:
    id: str  # assets/mascot の下のフォルダ名にもなる
    name: str
    role: str
    idle_lines: tuple[str, ...]
    lines: dict[str, str]

    @property
    def label(self) -> str:
        return f"{self.name}（{self.role}）"

    def line(self, key: str, **values) -> str:
        return self.lines[key].format(**values)


CHARACTERS = {
    "luce": Character(
        "luce", "ルーチェ", "聖女",
        (
            "異常なし！ちゃんと見てるよ。",
            "今日も結界はばっちり！",
            "怪しい通信が来たら止めるからね！",
        ),
        {
            "selected": "ルーチェだよ！見張りは任せて！",
            "start": "見張りを始めるよ！任せて！",
            "start_observe": "今日は見てるだけ！何も止めずに知らせるね。",
            "start_no_admin": "見張るよ！でも管理者権限がないから、止められないものもあるかも。",
            "stopped": "待って！{name} の通信を止めたよ！",
            "blocked": "待って！{name} が送信する前に止めたよ！",
            "stop_failed": "{name} を止められなかった！確認して！",
            "concerned": "{name} の通信、なんか気になる！",
            "keep_later": "あとで確認してね。わたしをクリックすると開くよ。",
            "keep_stopped": "止めたままにしたよ。わたしをクリックするとまた確認できるよ。",
            "status": "{state}！外部との通信 {count} 件を見てるよ。",
            "pause": "{minutes}分だけ休むね！その間は見張ってないから気をつけて。",
            "resume": "戻ったよ！続きも任せて！",
            "down": "大変、監視が止まってる！今は守れてないよ。再起動してみて！",
            "demo": "これが警告画面だよ！今のは試験表示で、何も止めてないよ。",
            "art_loaded": "絵を {count} 枚読み込んだよ！",
            "art_missing": "絵が見つからなかったよ。置き場所: {folder}",
            "launch_stopped": "待って！{name} の起動が怪しいから止めたよ！",
            "launch_concerned": "{name} の起動、なんか気になる！",
            "exited_seen": "{name} が怪しいことをしてたよ！もう終わってるけど確認して！",
            "trap_hit": "{name} が罠に触った！情報を盗もうとしてるかも！",
            "strict_on": "厳格モードにしたよ。知らないプログラムは通さないからね！",
            "strict_off": "厳格モードをやめたよ。",
            "inspected_bad": "{name} を調べたら、危険な点が {count} 件あったよ！見て！",
            "inspected_warn": "{name} を調べたよ。注意点が {count} 件あるよ。",
            "sysmon_stopped": "大変、Sysmonが止まってる！心当たりがなければ確認して！",
            "sysmon_back": "Sysmonが動き出したよ！",
            "self_restarted": "わたし、止められちゃったみたい！起動し直したよ。心当たりがなければ気をつけて！",
            "guard_restarted": "見張り役が止まってたから、起動し直したよ！",
        },
    ),
    "ansel": Character(
        "ansel", "アンセル", "神父",
        (
            "異常はありません。ご安心ください。",
            "帳簿も今のところ静かなものです。",
            "気になる通信があれば、すぐお知らせします。",
        ),
        {
            "selected": "アンセルです。見回りを引き継ぎますね。",
            "start": "見回りを始めます。どうぞお仕事を続けてください。",
            "start_observe": "今日は記録だけいたします。何も止めません。",
            "start_no_admin": "管理者権限がありませんので、止められないものがあるかもしれません。",
            "stopped": "そこまでです。{name} の通信を止めました。",
            "blocked": "送信の前に、{name} の接続を止めました。",
            "stop_failed": "{name} を止められませんでした。ご確認をお願いします。",
            "concerned": "{name} の通信が少し気になります。",
            "keep_later": "後ほどご確認ください。私をクリックすると開きます。",
            "keep_stopped": "止めたままにしました。私をクリックすると、また確認できます。",
            "status": "{state}です。外部との通信 {count} 件を見ています。",
            "pause": "{minutes}分ほど休ませていただきます。その間は見張っていません。",
            "resume": "見回りに戻りました。",
            "down": "監視が止まっています。今は守れていません。再起動をお願いします。",
            "demo": "こちらが警告画面です。今のは試験表示で、何も止めていません。",
            "art_loaded": "絵を {count} 枚読み込みました。",
            "art_missing": "絵が見つかりませんでした。置き場所: {folder}",
            "launch_stopped": "お待ちください。{name} の起動が不審ですので止めました。",
            "launch_concerned": "{name} の起動が少し気になります。",
            "exited_seen": "{name} に不審な動きがありました。すでに終了しています。ご確認ください。",
            "trap_hit": "{name} が罠に触れました。情報を盗もうとしている恐れがあります。",
            "strict_on": "厳格モードにいたしました。存じ上げないプログラムはお通ししません。",
            "strict_off": "厳格モードを解除しました。",
            "inspected_bad": "{name} を調べました。危険な点が {count} 件あります。ご確認ください。",
            "inspected_warn": "{name} を調べました。注意点が {count} 件あります。",
            "sysmon_stopped": "Sysmonが止まっています。お心当たりがなければご確認ください。",
            "sysmon_back": "Sysmonが動き始めました。",
            "self_restarted": "私が止められたようです。起動し直しました。お心当たりがなければご注意ください。",
            "guard_restarted": "見張り役が止まっていたので、起動し直しました。",
        },
    ),
    "silva": Character(
        "silva", "シルヴァ", "狼の番人",
        (
            "……異常なし。",
            "今日も嫌な匂いはしないね。",
            "変なのが来たら、あたしが止める。",
        ),
        {
            "selected": "シルヴァだ。見張りは任せな。",
            "start": "見回りを始める。あんたは自分の仕事をしな。",
            "start_observe": "今日は嗅ぐだけにしとく。止めはしない。",
            "start_no_admin": "権限がないから、止めきれないのもいるかもね。",
            "stopped": "……{name} の通信、止めた。安心しな。",
            "blocked": "{name} が外へ出ようとした。出る前に止めたよ。",
            "stop_failed": "{name} を止めきれなかった。確かめてくれ。",
            "concerned": "{name} の通信、少し匂うね。",
            "keep_later": "あとで見な。あたしをクリックすれば開く。",
            "keep_stopped": "止めたままにしといた。あたしをクリックすればまた見られる。",
            "status": "{state}。外とのつながりを {count} 件見張ってる。",
            "pause": "{minutes}分だけ休む。その間は見てないから気をつけな。",
            "resume": "戻った。続けるよ。",
            "down": "監視が止まってる。今は守れてない。起動し直しな。",
            "demo": "これが警告の画面だ。今のは試しで、何も止めてない。",
            "art_loaded": "絵を {count} 枚読み込んだ。",
            "art_missing": "絵が見つからない。置き場所: {folder}",
            "launch_stopped": "{name} の起動が怪しい。止めといたよ。",
            "launch_concerned": "{name} の起動、少し匂う。",
            "exited_seen": "{name} が妙な真似をしてた。もう消えたけど、確かめな。",
            "trap_hit": "{name} が罠に食いついた。何か盗む気だね。",
            "strict_on": "厳格にいく。知らない奴は通さない。",
            "strict_off": "厳格モードは解いた。",
            "inspected_bad": "{name} を調べた。危ない点が {count} 件ある。見な。",
            "inspected_warn": "{name} を調べた。気になる点が {count} 件。",
            "sysmon_stopped": "Sysmonが止まった。心当たりがないなら、何かいるよ。",
            "sysmon_back": "Sysmonが戻った。",
            "self_restarted": "……あたしが止められた。戻ってきたけど、気をつけな。",
            "guard_restarted": "見張り役が止まってたから、起こしといた。",
        },
    ),
}


# キャラクターを表示しないときの通知の文。選択肢には出さない
PLAIN = Character(
    "plain", "まもるん", "表示なし",
    (),
    {
        "selected": "キャラクターの表示を切り替えました。",
        "start": "見張りを開始しました。",
        "start_observe": "観察モードで開始しました。何も止めません。",
        "start_no_admin": "管理者権限なしで開始しました。一部のプログラムと接続は止められません。",
        "stopped": "{name} の通信を止めました。",
        "blocked": "{name} の接続を送信前に止めました。",
        "stop_failed": "{name} を止められませんでした。確認してください。",
        "concerned": "{name} の通信に確認が必要です。",
        "keep_later": "あとで確認できます。トレイのメニューから開いてください。",
        "keep_stopped": "止めたままにしました。トレイのメニューから確認できます。",
        "status": "{state}。外部との通信 {count} 件を見ています。",
        "pause": "{minutes}分間、見張りを休みます。",
        "resume": "見張りを再開しました。",
        "down": "監視が止まっています。再起動してください。",
        "demo": "警告画面の試験表示を閉じました。何も止めていません。",
        "art_loaded": "絵を {count} 枚読み込みました。",
        "art_missing": "絵が見つかりません。置き場所: {folder}",
        "launch_stopped": "{name} の起動が不審なので止めました。",
        "launch_concerned": "{name} の起動に確認が必要です。",
        "exited_seen": "{name} に不審な動きがありました。すでに終了しています。",
        "trap_hit": "{name} が罠のファイルを読みました。",
        "strict_on": "厳格モードにしました。",
        "strict_off": "厳格モードを解除しました。",
        "inspected_bad": "{name} に危険な点が {count} 件あります。",
        "inspected_warn": "{name} に注意点が {count} 件あります。",
        "sysmon_stopped": "Sysmonが止まっています。心当たりがなければ確認してください。",
        "sysmon_back": "Sysmonが動き始めました。",
        "self_restarted": "まもるんが止められたので、起動し直しました。心当たりがなければ注意してください。",
        "guard_restarted": "見張り役が止まっていたので、起動し直しました。",
    },
)


def get_character(character_id) -> Character:
    """保存された設定が不正でも起動できるよう、不明な値は既定のキャラにする。"""
    if isinstance(character_id, str) and character_id in CHARACTERS:
        return CHARACTERS[character_id]
    return CHARACTERS[DEFAULT_CHARACTER]
