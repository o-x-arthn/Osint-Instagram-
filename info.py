from typing import Dict, List, Any
from datetime import datetime
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO, format='\033[1;94m%(asctime)s - %(levelname)s - %(message)s\033[0m')
logger = logging.getLogger('ArthnOSINT')

def format_output(data: Dict[str, Any], input_followers: int, follower_relationships: List[Dict[str, Any]]) -> str:
    output = f"\033[1;92m{'='*60}\nArthn’s OSINT Intelligence Report\n{'='*60}\033[0m\n"

    output += f"\033[1;94mTarget Username:\033[0m \033[1;93m{data.get('username', 'Unknown')}\033[0m\n"
    output += f"\033[1;94mQueried Username:\033[0m \033[1;93m{data.get('queried', 'Unknown')}\033[0m\n"
    output += f"\033[1;94mSource:\033[0m \033[1;93m{data.get('source', 'Unknown')}\033[0m\n"
    output += f"\033[1;94mUser ID:\033[0m \033[1;93m{data.get('user_id', 'Unknown')}\033[0m\n"
    output += f"\033[1;94mFollowers (Input):\033[0m \033[1;93m{input_followers}\033[0m\n"
    actual_followers = data.get('followers_count', 0)
    output += f"\033[1;94mFollowers (Actual):\033[0m \033[1;93m{actual_followers}\033[0m\n"
    output += f"\033[1;94mFollower Match:\033[0m \033[1;93m{'Yes' if abs(actual_followers - input_followers) < 100 else 'No'}\033[0m\n"
    output += f"\033[1;94mEstimated Account Creation:\033[0m \033[1;93m{data.get('account_age', 'Unknown')}\033[0m\n"
    output += f"\033[1;94mSensitive Data (Cookies):\033[0m \033[1;93m{data.get('sensitive_data', 'None found')}\033[0m\n"
    output += f"\033[1;94mHijacked Session ID:\033[0m \033[1;93m{data.get('hijacked_session', {}).get('new_sessionid', 'None found')}\033[0m\n"
    output += f"\033[1;94mHijacked Cookies:\033[0m \033[1;93m{data.get('hijacked_session', {}).get('cookies', 'None found')}\033[0m\n"
    output += f"\n\033[1;94m{'-'*40}\nAdditional Sensitive Data\033[0m\n"
    sensitive = data.get('additional_sensitive_data', {})
    output += f"\033[1;94m  Email:\033[0m \033[1;93m{sensitive.get('email', 'None')}\033[0m\n"
    output += f"\033[1;94m  Phone Number:\033[0m \033[1;93m{sensitive.get('phone_number', 'None')}\033[0m\n"
    output += f"\033[1;94m  Address:\033[0m \033[1;93m{sensitive.get('address', 'None')}\033[0m\n"
    output += f"\033[1;94m  City:\033[0m \033[1;93m{sensitive.get('city', 'None')}\033[0m\n"
    output += f"\033[1;94m  Zip Code:\033[0m \033[1;93m{sensitive.get('zip_code', 'None')}\033[0m\n"
    output += f"\033[1;94m  Additional Cookies:\033[0m \033[1;93m{sensitive.get('cookies', 'None found')}\033[0m\n"

    output += f"\n\033[1;94m{'-'*40}\nFollower Relationships\033[0m\n"
    for rel in follower_relationships:
        output += f"\033[1;94m  @{rel['username']}:\033[0m\n"
        output += f"\033[1;93m    Relationship:\033[0m {rel['relationship']}\n"
        output += f"\033[1;93m    Details:\033[0m {rel['details']}\n"
        output += f"\033[1;93m    Engagement Score:\033[0m {rel['engagement_score']:.2f}/10\n"
        output += f"\033[1;93m    Sentiment:\033[0m {rel['sentiment']}\n"
        output += f"\033[1;93m    Follower Info:\033[0m {rel['follower_data']['full_name']} ({rel['follower_data']['followers_count']} followers)\n"

    output += f"\n\033[1;94m{'-'*40}\nHashtags Used in Posts (Fetch #{data.get('hashtag_fetch_count', 0)})\033[0m\n"
    hashtag_freq = Counter(data.get("hashtags", [])).most_common(10)
    if hashtag_freq:
        for hashtag, count in hashtag_freq:
            output += f"\033[1;93m  #{hashtag}:\033[0m {count} times\n"
    else:
        output += "\033[1;93m  None found\033[0m\n"

    output += f"\n\033[1;94m{'-'*40}\nStories\033[0m\n"
    for story in data.get("stories", [])[:20]:
        if "error" in story:
            output += f"\033[1;91m  Error: {story['error']}\033[0m\n"
        else:
            output += f"\033[1;93m  ID:\033[0m {story['id']} | \033[1;93mDate:\033[0m {datetime.fromtimestamp(story['timestamp']).strftime('%Y-%m-%d %H:%M') if story['timestamp'] else 'Unknown'} | \033[1;93mURL:\033[0m {story.get('url', 'None')}\n"

    output += f"\n\033[1;94m{'-'*40}\nHighlights (Archived Stories)\033[0m\n"
    for highlight in data.get("highlights", [])[:20]:
        if "error" in highlight:
            output += f"\033[1;91m  Error: {highlight['error']}\033[0m\n"
        else:
            output += f"\033[1;93m  ID:\033[0m {highlight['id']} | \033[1;93mTitle:\033[0m {highlight['title']} | \033[1;93mDate:\033[0m {datetime.fromtimestamp(highlight['timestamp']).strftime('%Y-%m-%d %H:%M') if highlight['timestamp'] else 'Unknown'} | \033[1;93mURL:\033[0m {highlight.get('url', 'None')}\n"

    output += f"\n\033[1;94m{'-'*40}\nTagged Users\033[0m\n"
    tagged_freq = Counter(data.get("tagged_users", [])).most_common(10)
    if tagged_freq:
        for user, count in tagged_freq:
            output += f"\033[1;93m  @{user}:\033[0m {count} times\n"
    else:
        output += "\033[1;93m  None found\033[0m\n"

    output += f"\n\033[1;94m{'-'*40}\nProfile Details\033[0m\n"
    output += f"\033[1;93m  Full Name:\033[0m {data.get('full_name', 'Unknown')}\n"
    output += f"\033[1;93m  Biography:\033[0m {data.get('biography', 'No bio')}\n"
    output += f"\033[1;93m  Bio Links:\033[0m {', '.join(data.get('bio_links', [])) or 'None'}\n"
    output += f"\033[1;93m  Pronouns:\033[0m {', '.join(data.get('pronouns', [''])) or 'None'}\n"
    output += f"\033[1;93m  Following:\033[0m {data.get('following_count', 0)}\n"
    output += f"\033[1;93m  Post Count:\033[0m {data.get('post_count', 0)}\n"
    output += f"\033[1;93m  Highlight Reel Count:\033[0m {data.get('highlight_reel_count', 0)}\n"
    output += f"\033[1;93m  Private Account:\033[0m {data.get('is_private', False)}\n"
    output += f"\033[1;93m  Verified:\033[0m {data.get('is_verified', False)}\n"
    output += f"\033[1;93m  Business Account:\033[0m {data.get('is_business_account', False)}\n"
    output += f"\033[1;93m  Professional Account:\033[0m {data.get('is_professional_account', False)}\n"
    output += f"\033[1;93m  Blocked by Viewer:\033[0m {data.get('blocked_by_viewer', False)}\n"
    output += f"\033[1;93m  Restricted by Viewer:\033[0m {data.get('restricted_by_viewer', False)}\n"
    output += f"\033[1;93m  Has Blocked Viewer:\033[0m {data.get('has_blocked_viewer', False)}\n"
    output += f"\033[1;93m  Country Block:\033[0m {data.get('country_block', False)}\n"
    output += f"\033[1;93m  Has AR Effects:\033[0m {data.get('has_ar_effects', False)}\n"
    output += f"\033[1;93m  Has Clips:\033[0m {data.get('has_clips', False)}\n"
    output += f"\033[1;93m  Has Guides:\033[0m {data.get('has_guides', False)}\n"
    output += f"\033[1;93m  Has Chaining:\033[0m {data.get('has_chaining', False)}\n"
    output += f"\033[1;93m  Has Channel:\033[0m {data.get('has_channel', False)}\n"
    output += f"\033[1;93m  Is Supervision Enabled:\033[0m {data.get('is_supervision_enabled', False)}\n"
    output += f"\033[1;93m  Is Embeds Disabled:\033[0m {data.get('is_embeds_disabled', False)}\n"
    output += f"\033[1;93m  Is Joined Recently:\033[0m {data.get('is_joined_recently', False)}\n"
    output += f"\033[1;93m  Pinned Channels List Count:\033[0m {data.get('pinned_channels_list_count', 0)}\n"
    output += f"\033[1;93m  Profile Picture Present:\033[0m {data.get('profile_picture_present', False)}\n"
    output += f"\033[1;93m  Requested by Viewer:\033[0m {data.get('requested_by_viewer', False)}\n"
    output += f"\033[1;93m  Show Account Transparency Details:\033[0m {data.get('show_account_transparency_details', False)}\n"
    output += f"\033[1;93m  Category:\033[0m {data.get('category', 'None')}\n"
    output += f"\033[1;93m  External URL:\033[0m {data.get('external_url', 'None')}\n"
    output += f"\033[1;93m  Business Email:\033[0m {data.get('business_email', 'None')}\n"
    output += f"\033[1;93m  Business Phone:\033[0m {data.get('business_phone', 'None')}\n"

    output += f"\n\033[1;94m{'-'*40}\nBio Analysis\033[0m\n"
    bio = data.get("bio_analysis", {})
    output += f"\033[1;93m  Emails:\033[0m {', '.join(bio.get('emails', [])) or 'None'}\n"
    output += f"\033[1;93m  Social Handles:\033[0m {', '.join(bio.get('social_handles', [])) or 'None'}\n"
    output += f"\033[1;93m  Phone Numbers:\033[0m {', '.join(bio.get('phone_numbers', [])) or 'None'}\n"

    output += f"\n\033[1;94m{'-'*40}\nRelationships\033[0m\n"
    for user, info in data.get("relationships", {}).items():
        output += f"\033[1;93m  @{user}:\033[0m {info['classification']} (Mentions: {info['mention_count']}, Mutual: {info['is_mutual']})\n"

    output += f"\n\033[1;94m{'-'*40}\nEstimated Location\033[0m\n"
    loc = data.get("estimated_location", {})
    output += f"\033[1;93m  Country:\033[0m {loc.get('country', 'Unknown')}\n"
    output += f"\033[1;93m  Region:\033[0m {loc.get('region', 'Unknown')}\n"

    output += f"\n\033[1;94m{'-'*40}\nUsername History\033[0m\n"
    for snapshot in data.get("username_history", [])[:10]:
        output += f"\033[1;93m  Timestamp:\033[0m {snapshot['timestamp']} | \033[1;93mURL:\033[0m {snapshot['url']}\n"

    output += f"\n\033[1;94m{'-'*40}\nHashtag Interests\033[0m\n"
    for category, hashtags in data.get("hashtag_interests", {}).items():
        output += f"\033[1;93m  {category.capitalize()}:\033[0m {', '.join([f'#{h['hashtag']} ({h['count']})' for h in hashtags])}\n"

    output += f"\n\033[1;94m{'-'*40}\nHashtag Co-occurrence\033[0m\n"
    for pair, count in data.get("hashtag_cooccurrence", {}).items():
        output += f"\033[1;93m  {pair}:\033[0m {count} times\n"

    output += f"\n\033[1;94m{'-'*40}\nContent Types\033[0m\n"
    for content_type, ratio in data.get("content_types", {}).items():
        output += f"\033[1;93m  {content_type}:\033[0m {ratio:.2%}\n"

    output += f"\n\033[1;94m{'-'*40}\nSentiment Analysis\033[0m\n"
    sentiment = data.get("sentiment_analysis", {})
    output += f"\033[1;93m  Caption Sentiment:\033[0m Positive {sentiment.get('caption_sentiment', {}).get('positive_ratio', 0):.2%}, Negative {sentiment.get('caption_sentiment', {}).get('negative_ratio', 0):.2%}\n"
    output += f"\033[1;93m  Comment Sentiment:\033[0m Positive {sentiment.get('comment_sentiment', {}).get('positive_ratio', 0):.2%}, Negative {sentiment.get('comment_sentiment', {}).get('negative_ratio', 0):.2%}\n"

    output += f"\n\033[1;94m{'-'*40}\nLocation Timeline\033[0m\n"
    for loc in data.get("location_timeline", [])[:10]:
        output += f"\033[1;93m  {loc['location']}:\033[0m {loc['timestamp']}\n"

    output += f"\n\033[1;94m{'-'*40}\nTop Commenters\033[0m\n"
    for username, info in data.get("commenters", {}).items():
        output += f"\033[1;93m  @{username}:\033[0m {info['comment_count']} comments\n"

    output += f"\n\033[1;94m{'-'*40}\nExternal Link Analysis\033[0m\n"
    ext = data.get("external_data", {})
    output += f"\033[1;93m  URL:\033[0m {ext.get('external_url', 'None')}\n"
    output += f"\033[1;93m  Page Title:\033[0m {ext.get('page_title', 'None')}\n"
    output += f"\033[1;93m  Emails:\033[0m {', '.join(ext.get('emails', [])) or 'None'}\n"
    output += f"\033[1;93m  Phone Numbers:\033[0m {', '.join(ext.get('phone_numbers', [])) or 'None'}\n"
    output += f"\033[1;93m  Social Links:\033[0m {', '.join(ext.get('social_links', [])) or 'None'}\n"

    output += f"\n\033[1;94m{'-'*40}\nPinned Posts\033[0m\n"
    for post in data.get("pinned_posts", [])[:5]:
        output += f"\033[1;93m  Post:\033[0m https://www.instagram.com/p/{post}/\n"

    output += f"\n\033[1;94m{'-'*40}\nRecent Posts\033[0m\n"
    for post in data.get("posts", [])[:5]:
        output += f"\033[1;93m  Post ID:\033[0m {post['post_id']}\n"
        output += f"\033[1;93m  Shortcode:\033[0m {post['shortcode']}\n"
        output += f"\033[1;93m  Date:\033[0m {datetime.fromtimestamp(post['timestamp']).strftime('%Y-%m-%d %H:%M') if post['timestamp'] else 'Unknown'}\n"
        output += f"\033[1;93m  Likes:\033[0m {post['likes']}\n"
        output += f"\033[1;93m  Comments:\033[0m {post['comments_count']}\n"
        output += f"\033[1;93m  Media Type:\033[0m {post['media_type']}\n"
        output += f"\033[1;93m  Caption:\033[0m {post['caption'][:100] + '...' if len(post['caption']) > 100 else post['caption']}\n"
        output += f"\033[1;93m  URL:\033[0m {post['url']}\n"
        output += f"\033[1;93m  Mentions:\033[0m {', '.join(post['mentions']) or 'None'}\n"
        output += f"\033[1;93m  Hashtags:\033[0m {', '.join(post['hashtags']) or 'None'}\n"
        output += f"\033[1;93m  Tagged Users:\033[0m {', '.join(post['tagged_users']) or 'None'}\n"
        output += f"\033[1;93m  Is Pinned:\033[0m {post['is_pinned']}\n"
        output += f"\033[1;93m  Is Sponsored:\033[0m {post['is_sponsored']}\n"
        output += "\n"

    return output
