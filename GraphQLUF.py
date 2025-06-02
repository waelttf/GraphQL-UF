# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JSplitPane,
    JPopupMenu, JMenuItem, JTextField, JLabel, JOptionPane
)
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing import RowFilter, SortOrder
from java.awt import BorderLayout
from java.awt.event import MouseAdapter
from java.util import Comparator
import hashlib
import json


class NumericComparator(Comparator):
    def compare(self, a, b):
        try:
            return int(a) - int(b)
        except:
            return 0


class BurpExtender(IBurpExtender, ITab, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GraphQL Unique Finder")

        self.graphql_requests = []

        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        self._setup_ui()
        callbacks.addSuiteTab(self)

    def _setup_ui(self):
        self._main_panel = JPanel(BorderLayout())

        # Top panel with Start button, Clear All button and Search field
        top_panel = JPanel()
        self._start_button = JButton("Start", actionPerformed=self._run_analysis)
        self._clear_all_button = JButton("Clear All", actionPerformed=self._clear_all)
        self._search_field = JTextField(20)
        self._search_field.getDocument().addDocumentListener(SearchListener(self))

        top_panel.add(self._start_button)
        top_panel.add(self._clear_all_button)
        top_panel.add(JLabel("Search Operation:"))
        top_panel.add(self._search_field)

        self._main_panel.add(top_panel, BorderLayout.NORTH)

        self._column_names = ["ID", "Method", "URL", "Operation"]
        self._table_model = self._create_table_model()
        self._table = JTable(self._table_model)

        # Set up sorting
        self._sorter = TableRowSorter(self._table_model)
        self._sorter.setComparator(0, NumericComparator())
        self._table.setRowSorter(self._sorter)

        sortKeys = [TableRowSorter.SortKey(0, SortOrder.ASCENDING)]
        self._sorter.setSortKeys(sortKeys)

        self._table.getSelectionModel().addListSelectionListener(self._on_row_select)

        # Right-click menu
        self._popup_menu = JPopupMenu()
        menu_item_repeater = JMenuItem("Send to Repeater", actionPerformed=self._send_to_repeater)
        self._popup_menu.add(menu_item_repeater)

        menu_item_clear = JMenuItem("Clear Row", actionPerformed=self._clear_selected_row)
        self._popup_menu.add(menu_item_clear)

        self._table.addMouseListener(TableMouseAdapter(self._table, self._popup_menu))

        # Request/Response viewers
        viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewer_split.setLeftComponent(self._requestViewer.getComponent())
        viewer_split.setRightComponent(self._responseViewer.getComponent())
        viewer_split.setResizeWeight(0.5)

        # Table + Viewers split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setTopComponent(JScrollPane(self._table))
        split_pane.setBottomComponent(viewer_split)
        split_pane.setResizeWeight(0.5)

        self._main_panel.add(split_pane, BorderLayout.CENTER)

    def _create_table_model(self):
        class NonEditableModel(DefaultTableModel):
            def isCellEditable(self, row, col):
                return False
        return NonEditableModel([], self._column_names)

    def _run_analysis(self, event):
        self.graphql_requests = []
        self._table_model.setRowCount(0)

        seen_hashes = set()
        http_items = self._callbacks.getProxyHistory()

        for idx, item in enumerate(http_items, 1):
            request_info = self._helpers.analyzeRequest(item)
            url = request_info.getUrl().toString()

            if "/graphql" in url.lower() or any("graphql" in h.lower() for h in request_info.getHeaders()):
                body = self._helpers.bytesToString(item.getRequest()[request_info.getBodyOffset():])
                try:
                    json_body = json.loads(body)
                    query = json_body.get("query", "")
                    op_name = json_body.get("operationName", "Unnamed")

                    if query:
                        key = hashlib.sha256(query.encode()).hexdigest()
                        if key not in seen_hashes:
                            seen_hashes.add(key)
                            self.graphql_requests.append((item, {
                                "id": len(self.graphql_requests) + 1,
                                "method": request_info.getMethod(),
                                "url": url,
                                "operation": op_name
                            }))
                except:
                    continue

        for _, meta in self.graphql_requests:
            self._table_model.addRow([
                meta["id"],
                meta["method"],
                meta["url"],
                meta["operation"]
            ])

        sortKeys = [TableRowSorter.SortKey(0, SortOrder.ASCENDING)]
        self._sorter.setSortKeys(sortKeys)

    def _on_row_select(self, event):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        sorter = self._table.getRowSorter()
        model_index = sorter.convertRowIndexToModel(row)
        item = self.graphql_requests[model_index][0]
        self._requestViewer.setMessage(item.getRequest(), True)
        self._responseViewer.setMessage(item.getResponse(), False)

    def _send_to_repeater(self, event):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        sorter = self._table.getRowSorter()
        model_index = sorter.convertRowIndexToModel(row)
        item = self.graphql_requests[model_index][0]
        service = item.getHttpService()
        req_bytes = item.getRequest()

        self._callbacks.sendToRepeater(
            service.getHost(),
            service.getPort(),
            service.getProtocol() == "https",
            req_bytes,
            "GraphQL-Op"
        )

    def _clear_selected_row(self, event):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        sorter = self._table.getRowSorter()
        model_index = sorter.convertRowIndexToModel(row)

        confirm = JOptionPane.showConfirmDialog(
            None,
            "Are you sure you want to remove the selected row?",
            "Confirm Row Removal",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            del self.graphql_requests[model_index]
            self._table_model.removeRow(model_index)
            if self._table.getRowCount() == 0:
                self._requestViewer.setMessage(b"", True)
                self._responseViewer.setMessage(b"", False)

    def _clear_all(self, event):
        confirm = JOptionPane.showConfirmDialog(
            None,
            "Are you sure you want to clear all entries?",
            "Confirm Clear All",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.graphql_requests = []
            self._table_model.setRowCount(0)
            self._requestViewer.setMessage(b"", True)
            self._responseViewer.setMessage(b"", False)

    # IMessageEditorController methods
    def getHttpService(self): return None
    def getRequest(self): return None
    def getResponse(self): return None

    # ITab methods
    def getTabCaption(self): return "GraphQL UF"
    def getUiComponent(self): return self._main_panel


class TableMouseAdapter(MouseAdapter):
    def __init__(self, table, popup_menu):
        self.table = table
        self.popup_menu = popup_menu

    def mousePressed(self, evt): self._show_popup(evt)
    def mouseReleased(self, evt): self._show_popup(evt)

    def _show_popup(self, evt):
        if evt.isPopupTrigger():
            row = self.table.rowAtPoint(evt.getPoint())
            if row != -1:
                self.table.setRowSelectionInterval(row, row)
                self.popup_menu.show(self.table, evt.getX(), evt.getY())


class SearchListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender

    def insertUpdate(self, e): self._filter()
    def removeUpdate(self, e): self._filter()
    def changedUpdate(self, e): self._filter()

    def _filter(self):
        text = self.extender._search_field.getText().strip()
        if text == "":
            self.extender._sorter.setRowFilter(None)
        else:
            try:
                self.extender._sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text, 3))
            except:
                self.extender._sorter.setRowFilter(None)
