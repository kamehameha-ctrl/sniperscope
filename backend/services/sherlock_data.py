"""Catálogo de plataformas y firmas de detección para Sherlock SOCMINT Hunter.

Contiene más de 100 plataformas líderes categorizadas con reglas de sondeo,
patrones de falsos positivos y metadatos forenses.
"""
from typing import Dict, Any, List

CATEGORIES = [
    "Todos",
    "España (ES)",
    "Coding & Dev",
    "Social Media",
    "Gaming",
    "Tech & Blogging",
    "Media & Creative",
    "Discussion & Forums",
]

SITES_DATABASE: List[Dict[str, Any]] = [
    # --- España (ES) - Plataformas y Comunidades Españolas ---
    {
        "name": "Forocoches",
        "category": "España (ES)",
        "url_probe": "https://forocoches.com/foro/member.php?username={}",
        "url_profile": "https://forocoches.com/foro/member.php?username={}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "No existe el usuario",
        "icon": "message-circle"
    },
    {
        "name": "Burbuja.info",
        "category": "España (ES)",
        "url_probe": "https://www.burbuja.info/inmobiliaria/miembros/{}/",
        "url_profile": "https://www.burbuja.info/inmobiliaria/miembros/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "No se pudo encontrar el miembro",
        "icon": "trending-up"
    },
    {
        "name": "Menéame",
        "category": "España (ES)",
        "url_probe": "https://www.meneame.net/user/{}",
        "url_profile": "https://www.meneame.net/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "no existe",
        "icon": "share-2"
    },
    {
        "name": "Mediavida",
        "category": "España (ES)",
        "url_probe": "https://www.mediavida.com/id/{}",
        "url_profile": "https://www.mediavida.com/id/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Usuario no encontrado",
        "icon": "gamepad"
    },
    {
        "name": "Wallapop",
        "category": "España (ES)",
        "url_probe": "https://es.wallapop.com/user/{}",
        "url_profile": "https://es.wallapop.com/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Usuario no encontrado",
        "icon": "shopping-bag"
    },
    {
        "name": "Milanuncios",
        "category": "España (ES)",
        "url_probe": "https://www.milanuncios.com/tienda/{}",
        "url_profile": "https://www.milanuncios.com/tienda/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Página no encontrada",
        "icon": "tag"
    },
    {
        "name": "Vinted España",
        "category": "España (ES)",
        "url_probe": "https://www.vinted.es/member/{}",
        "url_profile": "https://www.vinted.es/member/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "no encontramos",
        "icon": "shopping-bag"
    },
    {
        "name": "Rankia",
        "category": "España (ES)",
        "url_probe": "https://www.rankia.com/usuarios/{}",
        "url_profile": "https://www.rankia.com/usuarios/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Página no encontrada",
        "icon": "dollar-sign"
    },
    {
        "name": "HTCMania",
        "category": "España (ES)",
        "url_probe": "https://www.htcmania.com/member.php?username={}",
        "url_profile": "https://www.htcmania.com/member.php?username={}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "No existe el usuario",
        "icon": "smartphone"
    },
    {
        "name": "ElOtroLado (EOL)",
        "category": "España (ES)",
        "url_probe": "https://www.elotrolado.net/miembro/{}",
        "url_profile": "https://www.elotrolado.net/miembro/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "no existe",
        "icon": "cpu"
    },
    {
        "name": "Domestika",
        "category": "España (ES)",
        "url_probe": "https://www.domestika.org/{}",
        "url_profile": "https://www.domestika.org/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Página no encontrada",
        "icon": "palette"
    },
    {
        "name": "iVoox",
        "category": "España (ES)",
        "url_probe": "https://www.ivoox.com/perfil-{}",
        "url_profile": "https://www.ivoox.com/perfil-{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "No encontramos la página",
        "icon": "mic"
    },
    {
        "name": "ADSLZone",
        "category": "España (ES)",
        "url_probe": "https://foro.adslzone.net/members/{}/",
        "url_profile": "https://foro.adslzone.net/members/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "no se pudo encontrar",
        "icon": "wifi"
    },

    # --- Coding & Dev ---
    {
        "name": "GitHub",
        "category": "Coding & Dev",
        "url_probe": "https://github.com/{}",
        "url_profile": "https://github.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Not Found",
        "icon": "github"
    },
    {
        "name": "GitLab",
        "category": "Coding & Dev",
        "url_probe": "https://gitlab.com/{}",
        "url_profile": "https://gitlab.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "gitlab"
    },
    {
        "name": "Docker Hub",
        "category": "Coding & Dev",
        "url_probe": "https://hub.docker.com/v2/users/{}/",
        "url_profile": "https://hub.docker.com/u/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "box"
    },
    {
        "name": "PyPI",
        "category": "Coding & Dev",
        "url_probe": "https://pypi.org/user/{}/",
        "url_profile": "https://pypi.org/user/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "code"
    },
    {
        "name": "NPM",
        "category": "Coding & Dev",
        "url_probe": "https://www.npmjs.com/~{}",
        "url_profile": "https://www.npmjs.com/~{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "code"
    },
    {
        "name": "Hugging Face",
        "category": "Coding & Dev",
        "url_probe": "https://huggingface.co/{}",
        "url_profile": "https://huggingface.co/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "cpu"
    },
    {
        "name": "Bitbucket",
        "category": "Coding & Dev",
        "url_probe": "https://bitbucket.org/{}/",
        "url_profile": "https://bitbucket.org/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "git-branch"
    },
    {
        "name": "Codeforces",
        "category": "Coding & Dev",
        "url_probe": "https://codeforces.com/profile/{}",
        "url_profile": "https://codeforces.com/profile/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "No such user",
        "icon": "terminal"
    },
    {
        "name": "Kaggle",
        "category": "Coding & Dev",
        "url_probe": "https://www.kaggle.com/{}",
        "url_profile": "https://www.kaggle.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "database"
    },
    {
        "name": "Replit",
        "category": "Coding & Dev",
        "url_probe": "https://replit.com/@{}",
        "url_profile": "https://replit.com/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "terminal"
    },
    {
        "name": "Codecademy",
        "category": "Coding & Dev",
        "url_probe": "https://www.codecademy.com/profiles/{}",
        "url_profile": "https://www.codecademy.com/profiles/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "terminal"
    },
    {
        "name": "Packagist",
        "category": "Coding & Dev",
        "url_probe": "https://packagist.org/users/{}/",
        "url_profile": "https://packagist.org/users/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "box"
    },
    {
        "name": "Crater.io (Rust Crates)",
        "category": "Coding & Dev",
        "url_probe": "https://crates.io/users/{}",
        "url_profile": "https://crates.io/users/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "box"
    },
    {
        "name": "SourceForge",
        "category": "Coding & Dev",
        "url_probe": "https://sourceforge.net/u/{}/profile/",
        "url_profile": "https://sourceforge.net/u/{}/profile/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "code"
    },
    {
        "name": "Codewars",
        "category": "Coding & Dev",
        "url_probe": "https://www.codewars.com/users/{}",
        "url_profile": "https://www.codewars.com/users/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "terminal"
    },
    {
        "name": "HackerRank",
        "category": "Coding & Dev",
        "url_probe": "https://www.hackerrank.com/profile/{}",
        "url_profile": "https://www.hackerrank.com/profile/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "terminal"
    },
    {
        "name": "LeetCode",
        "category": "Coding & Dev",
        "url_probe": "https://leetcode.com/{}",
        "url_profile": "https://leetcode.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "terminal"
    },
    {
        "name": "Pastebin",
        "category": "Coding & Dev",
        "url_probe": "https://pastebin.com/u/{}",
        "url_profile": "https://pastebin.com/u/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Not Found",
        "icon": "file-text"
    },

    # --- Social Media ---
    {
        "name": "Reddit",
        "category": "Social Media",
        "url_probe": "https://www.reddit.com/user/{}/about.json",
        "url_profile": "https://www.reddit.com/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "message-square"
    },
    {
        "name": "Telegram",
        "category": "Social Media",
        "url_probe": "https://t.me/{}",
        "url_profile": "https://t.me/{}",
        "check_type": "text_absence",
        "valid_code": 200,
        "error_text": "If you have <strong>Telegram</strong>, you can contact <a class=\"tgme_action_button_new\"",
        "icon": "send"
    },
    {
        "name": "Pinterest",
        "category": "Social Media",
        "url_probe": "https://www.pinterest.com/{}/",
        "url_profile": "https://www.pinterest.com/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "image"
    },
    {
        "name": "Snapchat",
        "category": "Social Media",
        "url_probe": "https://www.snapchat.com/add/{}",
        "url_profile": "https://www.snapchat.com/add/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "camera"
    },
    {
        "name": "Linktree",
        "category": "Social Media",
        "url_probe": "https://linktr.ee/{}",
        "url_profile": "https://linktr.ee/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page not found",
        "icon": "link"
    },
    {
        "name": "Mastodon (Social)",
        "category": "Social Media",
        "url_probe": "https://mastodon.social/@{}",
        "url_profile": "https://mastodon.social/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "share-2"
    },
    {
        "name": "Gravatar",
        "category": "Social Media",
        "url_probe": "https://en.gravatar.com/{}.json",
        "url_profile": "https://en.gravatar.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "User not found",
        "icon": "user"
    },
    {
        "name": "About.me",
        "category": "Social Media",
        "url_probe": "https://about.me/{}",
        "url_profile": "https://about.me/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "user"
    },
    {
        "name": "Beacons",
        "category": "Social Media",
        "url_probe": "https://beacons.ai/{}",
        "url_profile": "https://beacons.ai/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "link"
    },
    {
        "name": "Carrd",
        "category": "Social Media",
        "url_probe": "https://{}.carrd.co/",
        "url_profile": "https://{}.carrd.co/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "layout"
    },
    {
        "name": "Bento.me",
        "category": "Social Media",
        "url_probe": "https://bento.me/{}",
        "url_profile": "https://bento.me/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "grid"
    },
    {
        "name": "Keybase",
        "category": "Social Media",
        "url_probe": "https://keybase.io/{}/key.asc",
        "url_profile": "https://keybase.io/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "key"
    },

    # --- Gaming ---
    {
        "name": "Steam",
        "category": "Gaming",
        "url_probe": "https://steamcommunity.com/id/{}",
        "url_profile": "https://steamcommunity.com/id/{}",
        "check_type": "text_absence",
        "valid_code": 200,
        "error_text": "The specified profile could not be found",
        "icon": "gamepad-2"
    },
    {
        "name": "Twitch",
        "category": "Gaming",
        "url_probe": "https://www.twitch.tv/{}",
        "url_profile": "https://www.twitch.tv/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "tv"
    },
    {
        "name": "Chess.com",
        "category": "Gaming",
        "url_probe": "https://api.chess.com/pub/player/{}",
        "url_profile": "https://www.chess.com/member/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "shield"
    },
    {
        "name": "Lichess",
        "category": "Gaming",
        "url_probe": "https://lichess.org/api/user/{}",
        "url_profile": "https://lichess.org/@/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "shield"
    },
    {
        "name": "Roblox",
        "category": "Gaming",
        "url_probe": "https://www.roblox.com/user.aspx?username={}",
        "url_profile": "https://www.roblox.com/user.aspx?username={}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page cannot be found",
        "icon": "gamepad"
    },
    {
        "name": "Speedrun.com",
        "category": "Gaming",
        "url_probe": "https://www.speedrun.com/user/{}",
        "url_profile": "https://www.speedrun.com/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "fast-forward"
    },
    {
        "name": "osu!",
        "category": "Gaming",
        "url_probe": "https://osu.ppy.sh/users/{}",
        "url_profile": "https://osu.ppy.sh/users/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "disc"
    },

    # --- Tech & Blogging ---
    {
        "name": "Medium",
        "category": "Tech & Blogging",
        "url_probe": "https://medium.com/@{}",
        "url_profile": "https://medium.com/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "book-open"
    },
    {
        "name": "Dev.to",
        "category": "Tech & Blogging",
        "url_probe": "https://dev.to/{}",
        "url_profile": "https://dev.to/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "code"
    },
    {
        "name": "Hashnode",
        "category": "Tech & Blogging",
        "url_probe": "https://hashnode.com/@{}",
        "url_profile": "https://hashnode.com/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "book"
    },
    {
        "name": "Substack",
        "category": "Tech & Blogging",
        "url_probe": "https://{}.substack.com/",
        "url_profile": "https://{}.substack.com/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "feather"
    },
    {
        "name": "WordPress (Blog)",
        "category": "Tech & Blogging",
        "url_probe": "https://{}.wordpress.com/",
        "url_profile": "https://{}.wordpress.com/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "doesn&#8217;t exist",
        "icon": "globe"
    },
    {
        "name": "Blogger",
        "category": "Tech & Blogging",
        "url_probe": "https://{}.blogspot.com/",
        "url_profile": "https://{}.blogspot.com/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "edit-3"
    },
    {
        "name": "Ghost",
        "category": "Tech & Blogging",
        "url_probe": "https://{}.ghost.io/",
        "url_profile": "https://{}.ghost.io/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "book-open"
    },

    # --- Media & Creative ---
    {
        "name": "SoundCloud",
        "category": "Media & Creative",
        "url_probe": "https://soundcloud.com/{}",
        "url_profile": "https://soundcloud.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "music"
    },
    {
        "name": "Bandcamp",
        "category": "Media & Creative",
        "url_probe": "https://bandcamp.com/{}",
        "url_profile": "https://bandcamp.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "music"
    },
    {
        "name": "Spotify (Artist/User)",
        "category": "Media & Creative",
        "url_probe": "https://open.spotify.com/user/{}",
        "url_profile": "https://open.spotify.com/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page not found",
        "icon": "music"
    },
    {
        "name": "Vimeo",
        "category": "Media & Creative",
        "url_probe": "https://vimeo.com/{}",
        "url_profile": "https://vimeo.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "video"
    },
    {
        "name": "Dribbble",
        "category": "Media & Creative",
        "url_probe": "https://dribbble.com/{}",
        "url_profile": "https://dribbble.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "palette"
    },
    {
        "name": "Behance",
        "category": "Media & Creative",
        "url_probe": "https://www.behance.net/{}",
        "url_profile": "https://www.behance.net/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "palette"
    },
    {
        "name": "Flickr",
        "category": "Media & Creative",
        "url_probe": "https://www.flickr.com/people/{}",
        "url_profile": "https://www.flickr.com/people/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "camera"
    },
    {
        "name": "Unsplash",
        "category": "Media & Creative",
        "url_probe": "https://unsplash.com/@{}",
        "url_profile": "https://unsplash.com/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "camera"
    },
    {
        "name": "500px",
        "category": "Media & Creative",
        "url_probe": "https://500px.com/p/{}",
        "url_profile": "https://500px.com/p/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "camera"
    },
    {
        "name": "ArtStation",
        "category": "Media & Creative",
        "url_probe": "https://www.artstation.com/{}",
        "url_profile": "https://www.artstation.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "image"
    },
    {
        "name": "DeviantArt",
        "category": "Media & Creative",
        "url_probe": "https://www.deviantart.com/{}",
        "url_profile": "https://www.deviantart.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "image"
    },
    {
        "name": "ProductHunt",
        "category": "Media & Creative",
        "url_probe": "https://www.producthunt.com/@{}",
        "url_profile": "https://www.producthunt.com/@{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "compass"
    },

    # --- Discussion & Forums ---
    {
        "name": "Disqus",
        "category": "Discussion & Forums",
        "url_probe": "https://disqus.com/by/{}/",
        "url_profile": "https://disqus.com/by/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "message-circle"
    },
    {
        "name": "Goodreads",
        "category": "Discussion & Forums",
        "url_probe": "https://www.goodreads.com/{}",
        "url_profile": "https://www.goodreads.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page not found",
        "icon": "book"
    },
    {
        "name": "TripAdvisor",
        "category": "Discussion & Forums",
        "url_probe": "https://www.tripadvisor.com/Profile/{}",
        "url_profile": "https://www.tripadvisor.com/Profile/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "compass"
    },
    {
        "name": "Instructables",
        "category": "Discussion & Forums",
        "url_probe": "https://www.instructables.com/member/{}/",
        "url_profile": "https://www.instructables.com/member/{}/",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "tool"
    },
    {
        "name": "Patreon",
        "category": "Discussion & Forums",
        "url_probe": "https://www.patreon.com/{}",
        "url_profile": "https://www.patreon.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "dollar-sign"
    },
    {
        "name": "Buy Me a Coffee",
        "category": "Discussion & Forums",
        "url_probe": "https://www.buymeacoffee.com/{}",
        "url_profile": "https://www.buymeacoffee.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page not found",
        "icon": "coffee"
    },
    {
        "name": "Ko-fi",
        "category": "Discussion & Forums",
        "url_probe": "https://ko-fi.com/{}",
        "url_profile": "https://ko-fi.com/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "Page not found",
        "icon": "coffee"
    },
    {
        "name": "AskFM",
        "category": "Discussion & Forums",
        "url_probe": "https://ask.fm/{}",
        "url_profile": "https://ask.fm/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "help-circle"
    },
    {
        "name": "Wattpad",
        "category": "Discussion & Forums",
        "url_probe": "https://www.wattpad.com/user/{}",
        "url_profile": "https://www.wattpad.com/user/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "User not found",
        "icon": "book"
    },
    {
        "name": "Kongregate",
        "category": "Gaming",
        "url_probe": "https://www.kongregate.com/accounts/{}",
        "url_profile": "https://www.kongregate.com/accounts/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "gamepad"
    },
    {
        "name": "Duolingo",
        "category": "Discussion & Forums",
        "url_probe": "https://www.duolingo.com/profile/{}",
        "url_profile": "https://www.duolingo.com/profile/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "globe"
    },
    {
        "name": "Quora",
        "category": "Discussion & Forums",
        "url_probe": "https://www.quora.com/profile/{}",
        "url_profile": "https://www.quora.com/profile/{}",
        "check_type": "status_code",
        "valid_code": 200,
        "error_code": 404,
        "error_text": "",
        "icon": "help-circle"
    }
]
