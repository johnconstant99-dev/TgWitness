from . import account_report as view, case_assessment, report_layouts, snapshot_analytics


def document(context, title, blocks, *, sharing=False):
    say = view.Words(context.get('report_language', 'en'))
    design = view.Presentation.model_validate(context.get('presentation') or {}).design
    chapters = [chapter for chapter in report_layouts.chapter_plan(design, 'chat')
                if any(key in blocks for key in chapter.section_ids)]
    yield from view.opening(context, title, sharing=sharing)
    if design == 'reading_series':
        yield view.encoded('<div class="reading-series-shell"><aside class="reading-series-rail"><b>TgWitness</b>'
                           + report_layouts.navigation(chapters, say) + '</aside><div class="reading-series-paper">')
    else:
        yield view.encoded('<div class="ledger-margin-folio"><details class="ledger-margin-contents"><summary>'
                           + view.e(say('Contents')) + '</summary>' + report_layouts.navigation(chapters, say) + '</details>')
    for number, chapter in enumerate(chapters, 1):
        yield view.encoded(report_layouts.chapter_open(design, chapter, number, say))
        for key in chapter.section_ids:
            if key in blocks:
                for chunk in blocks[key]():
                    yield chunk if isinstance(chunk, bytes) else view.encoded(chunk)
        yield view.encoded(report_layouts.chapter_close(design))
    yield view.encoded('</div></div>' if design == 'reading_series' else '</div>')
    yield view.ending(say)


def index(context, chats):
    say = view.Words(context.get('report_language', 'en'))

    def scope():
        yield '<p class="notice">' + view.e(say('Original account data may contain personal information. Prepare a separate minimized copy before sharing.')) + '</p>'
        yield view.copy_context(context, say)
        yield view.scope(context.get('options', {}), say)

    blocks = {
        'case': lambda: (view.recipient_guide(say),),
        'assessment': lambda: (case_assessment.html(case_assessment.snapshot(context), say),),
        'selection': scope,
        'coverage': lambda: view.coverage_section(context, say),
        'analytics': lambda: (view.stats(context.get('counts', {}), say),
            snapshot_analytics.html_section(context.get('analytics'), context.get('presentation', {}), say)),
        'directory': lambda: view.chats_section(chats, say),
        'limitations': lambda: view.omissions_section(context, say),
        'verify': lambda: (view.verification(context, say),),
    }
    yield from document(context, say('Account export'), blocks)


def transcript(context, rows, *, chat=None, sharing=False):
    say = view.Words(context.get('report_language', 'en'))
    title = say('Sharing copy') if sharing else view.text(chat.get('title')) or str(chat.get('id', ''))

    def scope():
        if sharing:
            public = {key: context.get('policy', {}).get(key) for key in (*view.SCOPE_LABELS, 'purpose')}
            yield view.scope(public, say, sharing=True)
            yield '<p class="notice">' + view.e(say('This sharing copy is a separate derivative, not the complete original account export.')) + '</p>'
        yield view.copy_context(context, say, sharing=sharing)

    def introduction():
        if sharing:
            yield view.recipient_guide(say, sharing=True)
        else:
            yield '<p><a href="../index.html">← ' + view.e(say('Account export')) + '</a></p>'
            yield '<p>' + view.e(say('Message records are shown in captured page order. Signed JSONL remains authoritative.')) + '</p>'
            yield '<p>' + view.e(say('Cite the archive reference, the file path and the record reference beside a message. Record numbers apply only to this copy.')) + '</p>'

    def messages():
        yield '<section id="messages"><h2>' + view.e(say('Messages')) + '</h2>'
        if sharing:
            yield '<p class="muted">' + view.e(say('Record numbers follow messages.jsonl line order. They identify records in this copy, not original Telegram message IDs.')) + '</p>'
        pagination = {} if sharing else context.get('pagination') or {}
        if not sharing:
            yield view.page_navigation(context, say)
        path = pagination.get('file') or ('index.html' if sharing else 'chats/' + str(chat['id']) + '.html' if type(chat.get('id')) is int else 'chat.html')
        seen = False
        for number, row in enumerate(rows, pagination.get('first_record', 1)):
            seen = True
            yield view.message_card(row, say, prefix='' if sharing else '../', sharing=sharing, number=number, page_path=path)
        if not seen:
            yield '<p>' + view.e(say('No message records are included in this view. Check the scope and omissions before drawing conclusions.')) + '</p>'
        if not sharing:
            yield view.page_navigation(context, say)
        yield '</section>'

    assessment = case_assessment.snapshot(context, 'sharing' if sharing else 'account_chat',
                                         None if sharing else {'message_count': chat.get('message_count')})
    analytics = snapshot_analytics.html_section(context.get('analytics'), context.get('presentation', {}), say)
    figures = view.stats(context.get('counts', {}), say) if sharing else ''
    blocks = {
        'case': introduction,
        'assessment': lambda: (case_assessment.html(assessment, say),),
        'selection': scope,
        'journal': messages,
        'verify': lambda: (view.verification(context, say, sharing=sharing),),
    }
    if analytics or (sharing and context.get('counts')):
        blocks['analytics'] = lambda: (figures, analytics)
    yield from document(context, title, blocks, sharing=sharing)
