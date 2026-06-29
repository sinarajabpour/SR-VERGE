import { Box, Button, Tooltip } from '@mui/material'
import { useLockFn } from 'ahooks'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import {
  BaseEmpty,
  BasePage,
  BaseSearchBox,
  VirtualList,
  type VirtualListHandle,
} from '@/components/base'
import { ScrollTopButton } from '@/components/layout/scroll-top-button'
import { EditorViewer } from '@/components/profile/editor-viewer'
import { RulesEditorViewer } from '@/components/profile/rules-editor-viewer'
import { ProviderButton } from '@/components/rule/provider-button'
import RuleItem from '@/components/rule/rule-item'
import { useEditorDocument } from '@/hooks/use-editor-document'
import { useProfiles } from '@/hooks/use-profiles'
import { useVisibility } from '@/hooks/use-visibility'
import { useAppRefreshers, useRulesData } from '@/providers/app-data-context'
import {
  enhanceProfiles,
  readProfileFile,
  saveProfileFile,
} from '@/services/cmds'

const RulesPage = () => {
  const { t } = useTranslation()
  const { rules = [] } = useRulesData()
  const { refreshRules, refreshRuleProviders } = useAppRefreshers()
  const { current } = useProfiles()
  const [match, setMatch] = useState(() => (_: string) => true)
  const virtuosoRef = useRef<VirtualListHandle>(null)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const pageVisible = useVisibility()

  // Rule editing entry points (reuse the existing profile editors)
  const [rulesOpen, setRulesOpen] = useState(false)
  const [globalOpen, setGlobalOpen] = useState(false)

  const hasRulesEnhancement = !!current?.option?.rules

  const applyAndRefresh = useCallback(async () => {
    await enhanceProfiles()
    refreshRules()
  }, [refreshRules])

  const loadGlobalMerge = useCallback(() => readProfileFile('Merge'), [])
  const globalDocument = useEditorDocument({
    open: globalOpen,
    load: loadGlobalMerge,
  })

  const handleSaveGlobal = useLockFn(async () => {
    const currentValue = globalDocument.value
    if (!(await saveProfileFile('Merge', currentValue))) {
      await globalDocument.reload()
      return
    }
    globalDocument.markSaved(currentValue)
    await applyAndRefresh()
  })

  // 在组件挂载时和页面获得焦点时刷新规则数据
  useEffect(() => {
    refreshRules()
    refreshRuleProviders()

    if (pageVisible) {
      refreshRules()
      refreshRuleProviders()
    }
  }, [refreshRules, refreshRuleProviders, pageVisible])

  const filteredRules = useMemo(() => {
    const rulesWithLineNo = rules.map((item, index) => ({
      ...item,
      // UI-only derived data; keep app context/SWR data immutable
      lineNo: index + 1,
    }))

    return rulesWithLineNo.filter((item) => match(item.payload ?? ''))
  }, [rules, match])

  const handleScroll = useCallback((e: Event) => {
    setShowScrollTop((e.target as HTMLElement).scrollTop > 100)
  }, [])

  const scrollToTop = () => {
    virtuosoRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <BasePage
      full
      title={t('rules.page.title')}
      contentStyle={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'auto',
      }}
      header={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip
            title={
              !current
                ? t('rules.page.actions.noProfile')
                : !hasRulesEnhancement
                  ? t('rules.page.actions.noRulesEnhancement')
                  : ''
            }
          >
            <span>
              <Button
                size="small"
                variant="contained"
                disabled={!current || !hasRulesEnhancement}
                onClick={() => setRulesOpen(true)}
              >
                {t('rules.page.actions.editRules')}
              </Button>
            </span>
          </Tooltip>
          <Button
            size="small"
            variant="outlined"
            onClick={() => setGlobalOpen(true)}
          >
            {t('rules.page.actions.globalRules')}
          </Button>
          <ProviderButton />
        </Box>
      }
    >
      <Box
        sx={{
          pt: 1,
          mb: 0.5,
          mx: '10px',
          height: '36px',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <BaseSearchBox onSearch={(match) => setMatch(() => match)} />
      </Box>

      {filteredRules && filteredRules.length > 0 ? (
        <>
          <VirtualList
            ref={virtuosoRef}
            count={filteredRules.length}
            estimateSize={40}
            renderItem={(i) => <RuleItem value={filteredRules[i]} />}
            style={{ flex: 1 }}
            onScroll={handleScroll}
          />
          <ScrollTopButton onClick={scrollToTop} show={showScrollTop} />
        </>
      ) : (
        <BaseEmpty />
      )}

      {rulesOpen && current && (
        <RulesEditorViewer
          profileUid={current.uid}
          property={current.option?.rules ?? ''}
          groupsUid={current.option?.groups ?? ''}
          mergeUid={current.option?.merge ?? ''}
          open={true}
          onClose={() => setRulesOpen(false)}
          onSave={applyAndRefresh}
        />
      )}

      {globalOpen && (
        <EditorViewer
          open={true}
          title={t('profiles.components.more.global.merge')}
          value={globalDocument.value}
          language="yaml"
          path="rules-page:Merge.yaml"
          loading={globalDocument.loading}
          dirty={globalDocument.dirty}
          onChange={globalDocument.setValue}
          onSave={handleSaveGlobal}
          onClose={() => setGlobalOpen(false)}
        />
      )}
    </BasePage>
  )
}

export default RulesPage
